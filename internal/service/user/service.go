// Package user contains user-related application logic and validation.
package user

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"devinhadley/gobootstrapweb/internal/db"

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
	ErrLoginRateLimit     = errors.New("too many login attempts for email")
)

const (
	rateLimitLoginDurationMinutes = 10
	rateLimitLoginAttemptsAllowed = 10
)

type UserQueries interface {
	CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUserByEmail(ctx context.Context, email string) (db.User, error)
	GetUserByID(ctx context.Context, id int64) (db.User, error)
	CountFailedAuthAttemptsSince(ctx context.Context, arg db.CountFailedAuthAttemptsSinceParams) (int64, error)
	CreateLoginAuthAttempt(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error
	UpdatePasswordHash(ctx context.Context, arg db.UpdatePasswordHashParams) error
	DeactivateAllSessionsForUser(ctx context.Context, userID int64) error
}

type Service struct {
	queries         UserQueries
	commonPasswords commonPasswords
}

type AuthenticateBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func NewService(queries UserQueries) *Service {
	return &Service{queries: queries, commonPasswords: getCommonPasswords()}
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
		return User{}, ErrLoginRateLimit
	}

	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = s.createLoginAttempt(ctx, email, db.AuthOutcomeFailed)
			if err != nil {
				return User{}, err
			}
			return User{}, ErrInvalidCredentials
		}
		return User{}, fmt.Errorf("getting user by email: %w", err)
	}

	if !user.IsActive {
		err = s.createLoginAttempt(ctx, email, db.AuthOutcomeFailed)
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
		err = s.createLoginAttempt(ctx, email, db.AuthOutcomeFailed)
		if err != nil {
			return User{}, err
		}
		return User{}, ErrInvalidCredentials
	}

	err = s.createLoginAttempt(ctx, email, db.AuthOutcomeSucceeded)
	if err != nil {
		log.Printf("creating successful auth login attempt: %v", err)
	}

	return UserFromDB(user), nil
}

func (s *Service) ResetPasswordForAuthenticatedUser(ctx context.Context, user User, currentPassword string, newPassword string) (bool, error) {
	err := s.isValidPassword(newPassword)
	if err != nil {
		return false, err
	}

	ok, err := argon2.VerifyEncoded([]byte(currentPassword), []byte(user.DBUser().PasswordHash))
	if err != nil {
		return false, fmt.Errorf("validating password hash: %w", err)
	}

	if !ok {
		return false, ErrInvalidCredentials
	}

	newPasswordHash, err := createPasswordHash(newPassword)
	if err != nil {
		return false, fmt.Errorf("hashing password during authenticated reset: %w", err)
	}

	err = s.queries.UpdatePasswordHash(ctx, db.UpdatePasswordHashParams{
		ID:           user.DBUser().ID,
		PasswordHash: string(newPasswordHash),
	})
	if err != nil {
		return false, fmt.Errorf("updating password hash during authenticated password reset: %w", err)
	}

	// If for any reason we fail to deactivate sessions, we should still let the password reset go through.
	// This is still bad though and deactivation should be retried at some point.
	err = s.queries.DeactivateAllSessionsForUser(ctx, user.DBUser().ID)
	if err != nil {
		log.Printf("deactivating all sessions during authenticated password reset: %v", err)
		return true, nil
	}

	return true, nil
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

func (s *Service) createLoginAttempt(ctx context.Context, email string, outcome db.AuthOutcome) error {
	err := s.queries.CreateLoginAuthAttempt(ctx, db.CreateLoginAuthAttemptParams{
		Action:  db.AuthActionLogin,
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
