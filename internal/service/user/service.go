// Package user contains user-related application logic and validation.
package user

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/email"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matthewhartstonge/argon2"
)

var (
	ErrEmailBlank         = errors.New("invalid sign-up input")
	ErrInvalidLogInInput  = errors.New("invalid log-in input")
	ErrEmailTaken         = errors.New("email already in use")
	ErrInvalidEmail       = errors.New("email is not valid")
	ErrPasswordHashing    = errors.New("password hashing not implemented")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrPasswordEmpty      = errors.New("password cannot be empty")
	ErrPasswordShort      = errors.New("password cannot be empty")
	ErrPasswordLong       = errors.New("password cannot be empty")
	ErrPasswordCommon     = errors.New("password is too common")
	ErrUserNotFound       = errors.New("user not found")
	ErrRateLimit          = errors.New("too many attempts for action")
	ErrInvalidResetToken  = errors.New("invalid or expired reset token")
)

const (
	rateLimitLoginDurationMinutes              = 10
	rateLimitLoginAttemptsAllowed              = 10
	rateLimitPasswordResetShortDurationMinutes = 15
	rateLimitPasswordResetLongDurationMinutes  = 120
	rateLimitPasswordResetShortAllowed         = 2
	rateLimitPasswordResetLongAllowed          = 3
	passwordResetTokenDurationMinutes          = 15
)

type UserQueries interface {
	CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUserByEmail(ctx context.Context, email string) (db.User, error)
	GetUserByID(ctx context.Context, id int64) (db.User, error)
	CountFailedAuthAttemptsSince(ctx context.Context, arg db.CountFailedAuthAttemptsSinceParams) (int64, error)
	CountAuthAttemptsForPassResetReq(ctx context.Context, arg db.CountAuthAttemptsForPassResetReqParams) (db.CountAuthAttemptsForPassResetReqRow, error)
	CreateLoginAuthAttempt(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error
	CreatePasswordResetRequest(ctx context.Context, arg db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error)
	GetPasswordResetRequestByID(ctx context.Context, id []byte) (db.PasswordResetRequest, error)
	DeletePasswordResetRequestByID(ctx context.Context, id []byte) error
	UpdatePasswordHash(ctx context.Context, arg db.UpdatePasswordHashParams) error
	DeactivateAllSessionsForUser(ctx context.Context, userID int64) error
}

type Service struct {
	queries         UserQueries
	commonPasswords commonPasswords
	emailService    email.Service
	config          Config
}

type AuthenticateBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthenticatedPasswordResetBody struct {
	Password    string `json:"password"`
	NewPassword string `json:"newPassword"`
}

type CreatePasswordResetRequestBody struct {
	Email string `json:"email"`
}

type ResetPasswordFromResetRequestBody struct {
	NewPassword string `json:"newPassword"`
}

type Config struct {
	PasswordResetURL string
}

func NewService(queries UserQueries, emailService email.Service, config Config) *Service {
	if len(config.PasswordResetURL) > 0 && !strings.HasSuffix(config.PasswordResetURL, "/") {
		config.PasswordResetURL += "/"
	}

	return &Service{queries: queries, emailService: emailService, commonPasswords: getCommonPasswords(), config: config}
}

func (s *Service) SignUp(ctx context.Context, input AuthenticateBody) (User, error) {
	email, ok := trimAndRequireValue(input.Email)
	if !ok {
		return User{}, ErrEmailBlank
	}

	err := s.isValidPassword(input.Password)
	if err != nil {
		return User{}, err
	}

	email, ok = normalizeAndValidateEmail(email)
	if !ok {
		return User{}, ErrInvalidEmail
	}

	passwordHash, err := createPasswordHash(input.Password)
	if err != nil {
		return User{}, fmt.Errorf("when hashing password during sign up: %w", err)
	}

	user, err := s.queries.CreateUser(ctx, db.CreateUserParams{
		Email:        email,
		PasswordHash: string(passwordHash),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			if pgErr.ConstraintName == "users_email_key" {
				return User{}, ErrEmailTaken
			}
		}

		return User{}, fmt.Errorf("creating user: %w", err)
	}

	return UserFromDB(user), nil
}

func (s *Service) LogIn(ctx context.Context, input AuthenticateBody) (User, error) {
	email, ok := trimAndRequireValue(input.Email)
	if !ok {
		return User{}, ErrInvalidLogInInput
	}

	if input.Password == "" {
		return User{}, ErrInvalidLogInInput
	}

	email, ok = normalizeAndValidateEmail(email)
	if !ok {
		return User{}, ErrInvalidEmail
	}

	isLimited, err := s.isLoginRateLimited(ctx, email)
	if err != nil {
		return User{}, fmt.Errorf("checking if email ratelimited: %w", err)
	}

	if isLimited {
		return User{}, ErrRateLimit
	}

	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = s.createAuthAttempt(ctx, db.AuthActionLogin, email, db.AuthOutcomeFailed)
			if err != nil {
				return User{}, err
			}
			return User{}, ErrInvalidCredentials
		}
		return User{}, fmt.Errorf("getting user by email: %w", err)
	}

	if !user.IsActive {
		err = s.createAuthAttempt(ctx, db.AuthActionLogin, email, db.AuthOutcomeFailed)
		if err != nil {
			return User{}, err
		}
		return User{}, ErrInvalidCredentials
	}

	ok, err = argon2.VerifyEncoded([]byte(input.Password), []byte(user.PasswordHash))
	if err != nil {
		return User{}, fmt.Errorf("validating password hash: %w", err)
	}
	if !ok {
		err = s.createAuthAttempt(ctx, db.AuthActionLogin, email, db.AuthOutcomeFailed)
		if err != nil {
			return User{}, err
		}
		return User{}, ErrInvalidCredentials
	}

	err = s.createAuthAttempt(ctx, db.AuthActionLogin, email, db.AuthOutcomeSucceeded)
	if err != nil {
		log.Printf("creating successful auth login attempt: %v", err)
	}

	return UserFromDB(user), nil
}

func (s *Service) ResetPasswordForAuthenticatedUser(ctx context.Context, usr User, input AuthenticatedPasswordResetBody) error {
	err := s.isValidPassword(input.NewPassword)
	if err != nil {
		return err
	}

	ok, err := argon2.VerifyEncoded([]byte(input.Password), []byte(usr.DBUser().PasswordHash))
	if err != nil {
		return fmt.Errorf("validating password hash: %w", err)
	}

	if !ok {
		return ErrInvalidCredentials
	}

	newPasswordHash, err := createPasswordHash(input.NewPassword)
	if err != nil {
		return fmt.Errorf("hashing password during authenticated reset: %w", err)
	}

	err = s.queries.UpdatePasswordHash(ctx, db.UpdatePasswordHashParams{
		ID:           usr.DBUser().ID,
		PasswordHash: string(newPasswordHash),
	})
	if err != nil {
		return fmt.Errorf("updating password hash during authenticated password reset: %w", err)
	}

	// NOTE:
	// If for any reason we fail to deactivate sessions, we should still let the password reset go through.
	// This is still bad though and deactivation should be retried at some point.
	err = s.queries.DeactivateAllSessionsForUser(ctx, usr.DBUser().ID)
	if err != nil {
		log.Printf("deactivating all sessions during authenticated password reset: %v", err)
		return nil
	}

	return nil
}

func (s *Service) CreatePasswordResetRequest(ctx context.Context, reqBody CreatePasswordResetRequestBody) error {
	email, ok := normalizeAndValidateEmail(reqBody.Email)
	if !ok {
		return ErrInvalidEmail
	}

	isRateLimited, err := s.isPasswordResetReqRateLimited(ctx, email)
	if err != nil {
		return fmt.Errorf("checking if password reset request rate limited: %w", err)
	}

	if isRateLimited {
		return ErrRateLimit
	}

	usr, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Record failed auth attempt.
			return ErrUserNotFound
		}

		return fmt.Errorf("getting user by email when creating password reset request: %w", err)
	}

	resetToken := make([]byte, 16)
	_, err = rand.Read(resetToken)
	if err != nil {
		return fmt.Errorf("generating random bytes for password reset token: %w", err)
	}

	sum := sha256.Sum256(resetToken)
	_, err = s.queries.CreatePasswordResetRequest(ctx, db.CreatePasswordResetRequestParams{
		ID:     sum[:],
		UserID: usr.ID,
	})
	if err != nil {
		return fmt.Errorf("creating password reset request: %w", err)
	}

	encodedToken := base64.RawURLEncoding.EncodeToString(resetToken)
	urlWithToken := fmt.Sprintf("%v?token=%v", s.config.PasswordResetURL, encodedToken)
	err = s.emailService.SendMail(email, "Password Reset", urlWithToken)
	if err != nil {
		return fmt.Errorf("failed to send passwor reset email: %w", err)
	}

	err = s.createAuthAttempt(ctx, db.AuthActionPasswordReset, email, db.AuthOutcomeSucceeded)
	if err != nil {
		log.Printf("creating auth attempt for reset request: %v", err)
	}

	return nil
}

func (s *Service) ResetPasswordFromResetRequest(ctx context.Context, token string, input ResetPasswordFromResetRequestBody) error {
	err := s.isValidPassword(input.NewPassword)
	if err != nil {
		return err
	}

	resetToken, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return ErrInvalidResetToken
	}

	sum := sha256.Sum256(resetToken)
	resetRequest, err := s.queries.GetPasswordResetRequestByID(ctx, sum[:])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidResetToken
		}

		return fmt.Errorf("getting password reset request: %w", err)
	}

	expiresAt := resetRequest.CreatedAt.Time.Add(passwordResetTokenDurationMinutes * time.Minute)
	if time.Now().After(expiresAt) {
		return ErrInvalidResetToken
	}

	newPasswordHash, err := createPasswordHash(input.NewPassword)
	if err != nil {
		return fmt.Errorf("hashing password during reset from token: %w", err)
	}

	// TODO: Make updating hash & deleting password reset request a transaction.
	err = s.queries.UpdatePasswordHash(ctx, db.UpdatePasswordHashParams{
		ID:           resetRequest.UserID,
		PasswordHash: string(newPasswordHash),
	})
	if err != nil {
		return fmt.Errorf("updating password hash during reset from token: %w", err)
	}

	err = s.queries.DeletePasswordResetRequestByID(ctx, resetRequest.ID)
	if err != nil {
		return fmt.Errorf("deleting password reset request after successful reset: %w", err)
	}

	err = s.queries.DeactivateAllSessionsForUser(ctx, resetRequest.UserID)
	if err != nil {
		log.Printf("deactivating all sessions during reset from token: %v", err)
	}

	return nil
}

func (s *Service) GetUserByID(ctx context.Context, id int64) (User, error) {
	user, err := s.queries.GetUserByID(ctx, id)
	if err != nil {

		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}

		return User{}, fmt.Errorf("getting user by id: %w", err)

	}
	return UserFromDB(user), nil
}

func trimAndRequireValue(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", false
	}

	return trimmed, true
}

func (s *Service) isValidPassword(password string) error {
	if strings.TrimSpace(password) == "" {
		return ErrPasswordEmpty
	}

	if utf8.RuneCountInString(password) <= 12 {
		return ErrPasswordShort
	}

	if utf8.RuneCountInString(password) > 256 {
		return ErrPasswordLong
	}

	if s.commonPasswords.isCommonPassword(password) {
		return ErrPasswordCommon
	}

	return nil
}

func (s *Service) isLoginRateLimited(ctx context.Context, email string) (bool, error) {
	timeBefore := time.Now().Add(-(rateLimitLoginDurationMinutes * time.Minute))

	loginAttemptsForEmail, err := s.queries.CountFailedAuthAttemptsSince(ctx, db.CountFailedAuthAttemptsSinceParams{
		Action: db.AuthActionLogin,
		Email:  email,
		CreatedAt: pgtype.Timestamptz{
			Time:  timeBefore,
			Valid: true,
		},
	})
	if err != nil {
		return false, err
	}

	return loginAttemptsForEmail >= rateLimitLoginAttemptsAllowed, nil
}

func (s *Service) isPasswordResetReqRateLimited(ctx context.Context, email string) (bool, error) {
	now := time.Now()

	count, err := s.queries.CountAuthAttemptsForPassResetReq(ctx, db.CountAuthAttemptsForPassResetReqParams{
		RecentDate: pgtype.Timestamptz{
			Time:  now.Add(-(rateLimitPasswordResetShortDurationMinutes * time.Minute)),
			Valid: true,
		},
		OldDate: pgtype.Timestamptz{
			Time:  now.Add(-(rateLimitPasswordResetLongDurationMinutes * time.Minute)),
			Valid: true,
		},
		Email: email,
	})
	if err != nil {
		return false, err
	}

	return count.RecentCount >= rateLimitPasswordResetShortAllowed || count.OldCount >= rateLimitPasswordResetLongAllowed, nil
}

func (s *Service) createAuthAttempt(ctx context.Context, action db.AuthAction, email string, outcome db.AuthOutcome) error {
	err := s.queries.CreateLoginAuthAttempt(ctx, db.CreateLoginAuthAttemptParams{
		Action:  action,
		Email:   email,
		Outcome: outcome,
	})
	if err != nil {
		return fmt.Errorf("creating login auth attempt: %w", err)
	}

	return nil
}

func normalizeAndValidateEmail(input string) (string, bool) {
	email := strings.TrimSpace(input)

	if email == "" || len(email) > 254 {
		return "", false
	}

	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", false
	}
	if addr.Address != email {
		return "", false
	}

	if strings.Count(email, "@") != 1 {
		return "", false
	}

	parts := strings.Split(email, "@")
	local := parts[0]
	domain := parts[1]

	if local == "" || domain == "" {
		return "", false
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", false
	}
	if !strings.Contains(domain, ".") {
		return "", false
	}

	normalized := local + "@" + strings.ToLower(domain)
	return normalized, true
}

func createPasswordHash(password string) ([]byte, error) {
	argon := argon2.MemoryConstrainedDefaults()

	passwordHash, err := argon.HashEncoded([]byte(password))
	if err != nil {
		return nil, err
	}

	return passwordHash, nil
}
