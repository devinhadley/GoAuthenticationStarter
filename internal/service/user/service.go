// Package user contains user-related application logic and validation.
package user

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"unicode/utf8"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
)

type UserQueries interface {
	CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUserByEmail(ctx context.Context, email string) (db.User, error)
	GetUserByID(ctx context.Context, id int64) (db.User, error)
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

func (s *Service) SignUp(ctx context.Context, input AuthenticateBody) (db.User, error) {
	email, ok := trimAndRequireValue(input.Email)
	if !ok {
		return db.User{}, ErrEmailBlank
	}

	err := s.isValidPassword(input.Password)
	if err != nil {
		return db.User{}, err
	}

	ok, email = normalizeAndValidateEmail(email)
	if !ok {
		return db.User{}, ErrInvalidEmail
	}

	argon := argon2.MemoryConstrainedDefaults()

	passwordHash, err := argon.HashEncoded([]byte(input.Password))
	if err != nil {
		return db.User{}, fmt.Errorf("when hashing password: %w", err)
	}

	user, err := s.queries.CreateUser(ctx, db.CreateUserParams{
		Email:        email,
		PasswordHash: string(passwordHash),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			if pgErr.ConstraintName == "users_email_key" {
				return db.User{}, ErrEmailTaken
			}
		}

		return db.User{}, fmt.Errorf("creating user: %w", err)
	}

	return user, nil
}

func (s *Service) LogIn(ctx context.Context, input AuthenticateBody) (db.User, error) {
	email, ok := trimAndRequireValue(input.Email)
	if !ok {
		return db.User{}, ErrInvalidLogInInput
	}

	if input.Password == "" {
		return db.User{}, ErrInvalidLogInInput
	}

	ok, email = normalizeAndValidateEmail(email)
	if !ok {
		return db.User{}, ErrInvalidEmail
	}

	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, ErrInvalidCredentials
		}
		return db.User{}, fmt.Errorf("getting user by email: %w", err)
	}

	if !user.IsActive {
		return db.User{}, ErrInvalidCredentials
	}

	ok, err = argon2.VerifyEncoded([]byte(input.Password), []byte(user.PasswordHash))
	if err != nil {
		return db.User{}, fmt.Errorf("validating password hash: %w", err)
	}
	if !ok {
		return db.User{}, ErrInvalidCredentials
	}

	return user, nil
}

func (s *Service) GetUserByID(ctx context.Context, id int64) (db.User, error) {
	user, err := s.queries.GetUserByID(ctx, id)
	if err != nil {

		if errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, ErrUserNotFound
		}

		return db.User{}, fmt.Errorf("getting user by id: %w", err)

	}
	return user, nil
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

func normalizeAndValidateEmail(input string) (bool, string) {
	email := strings.TrimSpace(input)

	if email == "" || len(email) > 254 {
		return false, ""
	}

	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false, ""
	}
	if addr.Address != email {
		return false, ""
	}

	if strings.Count(email, "@") != 1 {
		return false, ""
	}

	parts := strings.Split(email, "@")
	local := parts[0]
	domain := parts[1]

	if local == "" || domain == "" {
		return false, ""
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false, ""
	}
	if !strings.Contains(domain, ".") {
		return false, ""
	}

	normalized := local + "@" + strings.ToLower(domain)
	return true, normalized
}
