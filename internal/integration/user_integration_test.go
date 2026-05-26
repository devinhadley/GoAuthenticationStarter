// Integration contains all integration tests and helpers. It is one package to streamline shared test dependencies like DB.
package integration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/email"
	"devinhadley/gobootstrapweb/internal/handlers"
	"devinhadley/gobootstrapweb/internal/middleware"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matthewhartstonge/argon2"
)

type userIntegrationDeps struct {
	pool           *pgxpool.Pool
	queries        *db.Queries
	userService    *user.Service
	sessionService *session.Service
	emailService   *email.SliceEmailService
	signUp         http.HandlerFunc
	login          http.HandlerFunc
	passwordReset  http.HandlerFunc
	tokenReset     http.HandlerFunc
}

func TestSignUpIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests in short mode")
	}

	t.Run("sign up succeeds and persists user", testSignUpSucceedsAndPersistsUser)
	t.Run("duplicate email returns bad request and does not create second user", testSignUpDuplicateEmail)
	t.Run("invalid email returns bad request and does not persist user", testSignUpRejectsInvalidEmail)
	t.Run("blank email returns bad request and does not persist user", testSignUpRejectsBlankEmail)
	t.Run("blank password returns bad request and does not persist user", testSignUpRejectsBlankPassword)
	t.Run("short password returns bad request and does not persist user", testSignUpRejectsShortPassword)
	t.Run("long password returns bad request and does not persist user", testSignUpRejectsLongPassword)
	t.Run("common password returns bad request and does not persist user", testSignUpRejectsCommonPassword)
}

func TestLogInIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests in short mode")
	}

	t.Run("login succeeds with valid credentials and creates session", testSuccessfulLogin)
	t.Run("returns unauthorized when user does not exist", testLogInReturnsUnauthorizedWhenUserDoesNotExist)
	t.Run("returns unauthorized when password is incorrect and doesnt create session", testLogInReturnsUnauthorizedWhenPasswordIsIncorrect)
	t.Run("returns 429 when rate limited and doesnt create session / auth attempt", testLogInReturnsTooManyRequestsWhenRateLimited)
	t.Run("login succeeds when one of ten failed attempts is older than ten minutes", testLogInSucceedsWhenOneFailedAttemptIsOlderThanWindow)
	t.Run("test rejects invalid email", testLogInRejectsInvalidEmail)
}

func TestPasswordResetIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests in short mode")
	}

	// authenticated password reset.
	t.Run("password reset succeeds with authenticated user and deactivates sessions", testAuthenticatedPasswordResetSucceeds)
	t.Run("password reset fails with incorrect password and doesnt deactivate sessions", testAuthenticatedPasswordResetFailsWithWrongPassword)
	t.Run("password reset fails with weak password and doesnt deactivate sessions", testAuthenticatedPasswordResetFailsWithWeakPassword)

	// token based password reset.
	t.Run("can create password reset request", testCanCreatePasswordResetRequest)
	t.Run("creating password reset request for unknown user returns 204", testCreatingPasswordResetRequestForUnknownUserReturns204)
	t.Run("creating 3 password resets in 15 minutes shows ratelimit error", testCreatingThreePasswordResetsIn15MinutesShowsRateLimitError)
	t.Run("creating 4 password resets in 2 hours shows ratelimit error", testCreatingFourPasswordResetsInTwoHoursShowsRateLimitError)

	t.Run("password reset suceeds with a valid reset token and deactivates sessions", testPasswordResetSucceedsWithValidResetTokenAndDeactivatesSessions)
	t.Run("cant reset password with incorrect token", testCantResetPasswordWithIncorrectToken)
	t.Run("cant reset password with already used token", testCantResetPasswordWithAlreadyUsedToken)
}

func testSignUpSucceedsAndPersistsUser(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	input := map[string]string{
		"email":    "signup@example.com",
		"password": "example-password",
	}

	rec := performJsonRequest(deps.signUp, http.MethodPost, "/signup", input)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusNoContent)
	}

	storedUser, err := deps.queries.GetUserByEmail(context.Background(), input["email"])
	if err != nil {
		t.Fatalf("failed to load user from database: %v", err)
	}

	if storedUser.ID == 0 {
		t.Fatal("expected stored user id to be non-zero")
	}

	if storedUser.Email != input["email"] {
		t.Fatalf("got stored email %q, want %q", storedUser.Email, input["email"])
	}

	ok, err := argon2.VerifyEncoded([]byte(input["password"]), []byte(storedUser.PasswordHash))
	if err != nil {
		t.Fatalf("VerifyEncoded returned error: %v", err)
	}

	if !ok {
		t.Fatal("stored password hash does not match input password")
	}

	count, err := deps.queries.GetSessionCountByUser(context.Background(), storedUser.ID)
	if err != nil {
		t.Fatalf("got error %v when getting session count", err)
	}

	if count != 1 {
		t.Fatalf("got number of sessions for user %v wanted %v", count, 1)
	}

	assertSessionCookieExists(t, rec)
}

func testSignUpDuplicateEmail(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	input := map[string]string{
		"email":    "duplicate@example.com",
		"password": "example-password",
	}

	first := performJsonRequest(deps.signUp, http.MethodPost, "/signup", input)
	if first.Code != http.StatusNoContent {
		t.Fatalf("first sign up got status %d, want %d", first.Code, http.StatusNoContent)
	}

	second := performJsonRequest(deps.signUp, http.MethodPost, "/signup", input)
	if second.Code != http.StatusBadRequest {
		t.Fatalf("second sign up got status %d, want %d", second.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, second)
	if gotErr.Email != "email already in use" {
		t.Fatalf("got email error %q, want %q", gotErr.Email, "email already in use")
	}

	userCount := countUsersByEmail(t, deps.pool, input["email"])
	if userCount != 1 {
		t.Fatalf("got %d users for email %q, want 1", userCount, input["email"])
	}
}

func testSignUpRejectsBlankEmail(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	rec := performJsonRequest(deps.signUp, http.MethodPost, "/signup", map[string]string{
		"email":    "",
		"password": "example-password",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Email != "email may not be blank" {
		t.Fatalf("got email error %q, want %q", gotErr.Email, "email may not be blank")
	}

	userCount := countUsers(t, deps.pool)
	if userCount != 0 {
		t.Fatalf("got %d users in database, want 0", userCount)
	}
}

func testSignUpRejectsBlankPassword(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	email := "blank-password@example.com"
	rec := performJsonRequest(deps.signUp, http.MethodPost, "/signup", map[string]string{
		"email":    email,
		"password": "",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Password != "password can't be empty" {
		t.Fatalf("got password error %q, want %q", gotErr.Password, "password can't be empty")
	}

	assertNoUserWithEmail(t, deps.queries, email)
}

func testSignUpRejectsCommonPassword(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	rec := performJsonRequest(deps.signUp, http.MethodPost, "/signup", map[string]string{
		"email":    "test@example.com",
		"password": "123456789101112",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Password != "password too common" {
		t.Fatalf("got password error %q, want %q", gotErr.Password, "password too common")
	}

	userCount := countUsers(t, deps.pool)
	if userCount != 0 {
		t.Fatalf("got %d users in database, want 0", userCount)
	}
}

func testSignUpRejectsShortPassword(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	rec := performJsonRequest(deps.signUp, http.MethodPost, "/signup", map[string]string{
		"email":    "short-password@example.com",
		"password": "12345678901",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Password != "password must be 13 or more characters" {
		t.Fatalf("got password error %q, want %q", gotErr.Password, "password must be 12 or more characters")
	}

	userCount := countUsers(t, deps.pool)
	if userCount != 0 {
		t.Fatalf("got %d users in database, want 0", userCount)
	}
}

func testSignUpRejectsLongPassword(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	rec := performJsonRequest(deps.signUp, http.MethodPost, "/signup", map[string]string{
		"email":    "long-password@example.com",
		"password": strings.Repeat("a", 257),
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Password != "password must be 256 charactrs or less" {
		t.Fatalf("got password error %q, want %q", gotErr.Password, "password must be 256 charactrs or less")
	}

	userCount := countUsers(t, deps.pool)
	if userCount != 0 {
		t.Fatalf("got %d users in database, want 0", userCount)
	}
}

func testSignUpRejectsInvalidEmail(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	email := "invalid"
	rec := performJsonRequest(deps.signUp, http.MethodPost, "/signup", map[string]string{
		"email":    email,
		"password": "example-password",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Email != "email is not valid" {
		t.Fatalf("got email error %q, want %q", gotErr.Email, "email is not valid")
	}

	userCount := countUsers(t, deps.pool)
	if userCount != 0 {
		t.Fatalf("got %d users in database, want 0", userCount)
	}
}

func testSuccessfulLogin(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()
	email := "test@example.com"

	user, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: "example-password",
	})
	if err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	rec := performJsonRequest(deps.login, http.MethodPost, "/login", map[string]string{
		"email":    email,
		"password": "example-password",
	})

	if rec.Code != http.StatusNoContent {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusNoContent)
	}

	// Session created for the user.
	count, err := deps.queries.GetSessionCountByUser(ctx, user.DBUser().ID)
	if err != nil {
		t.Fatalf("got error %v when getting session count", err)
	}

	if count != 1 {
		t.Fatalf("got number of sessions for user %v wanted %v", count, 1)
	}

	succeededCount := countAuthAttemptsByEmailAndOutcome(t, deps.pool, email, db.AuthOutcomeSucceeded)
	if succeededCount != 1 {
		t.Fatalf("got %d successful auth attempts for user %q, want %d", succeededCount, email, 1)
	}

	failedCount := countAuthAttemptsByEmailAndOutcome(t, deps.pool, email, db.AuthOutcomeFailed)
	if failedCount != 0 {
		t.Fatalf("got %d failed auth attempts for user %q, want %d", failedCount, email, 0)
	}

	assertSessionCookieExists(t, rec)
}

func testLogInRejectsInvalidEmail(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	email := "invalid"

	rec := performJsonRequest(deps.login, http.MethodPost, "/login", map[string]string{
		"email":    email,
		"password": "example-password",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Email != "email is not valid" {
		t.Fatalf("got email error %q, want %q", gotErr.Email, "email is not valid")
	}

	attemptCount := countAuthAttemptsByEmail(t, deps.pool, email)
	if attemptCount != 0 {
		t.Fatalf("got %d auth attempts for user %q, want %d", attemptCount, email, 0)
	}

	assertNoSessionCookie(t, rec)
}

func testLogInReturnsUnauthorizedWhenUserDoesNotExist(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	email := "missing@example.com"

	rec := performJsonRequest(deps.login, http.MethodPost, "/login", map[string]string{
		"email":    email,
		"password": "example-password",
	})

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "authentication failed" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "authentication failed")
	}

	attemptCount := countAuthAttemptsByEmail(t, deps.pool, email)
	if attemptCount != 1 {
		t.Fatalf("got %d auth attempts for user %q, want %d", attemptCount, email, 1)
	}

	failedCount := countAuthAttemptsByEmailAndOutcome(t, deps.pool, email, db.AuthOutcomeFailed)
	if failedCount != 1 {
		t.Fatalf("got %d failed auth attempts for user %q, want %d", failedCount, email, 1)
	}

	assertNoSessionCookie(t, rec)
}

func testLogInReturnsUnauthorizedWhenPasswordIsIncorrect(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()
	email := "wrong-password@example.com"

	user, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: "correct-password",
	})
	if err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	rec := performJsonRequest(deps.login, http.MethodPost, "/login", map[string]string{
		"email":    email,
		"password": "incorrect-password",
	})

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "authentication failed" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "authentication failed")
	}

	// Session not created for the user.
	count, err := deps.queries.GetSessionCountByUser(ctx, user.DBUser().ID)
	if err != nil {
		t.Fatalf("got error %v when getting session count", err)
	}

	if count != 0 {
		t.Fatalf("got number of sessions for user %v wanted %v", count, 0)
	}

	failedCount := countAuthAttemptsByEmailAndOutcome(t, deps.pool, email, db.AuthOutcomeFailed)
	if failedCount != 1 {
		t.Fatalf("got %d failed auth attempts for user %q, want %d", failedCount, email, 1)
	}

	succeededCount := countAuthAttemptsByEmailAndOutcome(t, deps.pool, email, db.AuthOutcomeSucceeded)
	if succeededCount != 0 {
		t.Fatalf("got %d successful auth attempts for user %q, want %d", succeededCount, email, 0)
	}

	assertNoSessionCookie(t, rec)
}

func testLogInReturnsTooManyRequestsWhenRateLimited(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()
	email := "rate-limited@example.com"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: "example-password",
	})
	if err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	for range 10 {
		err = deps.queries.CreateLoginAuthAttempt(ctx, db.CreateLoginAuthAttemptParams{
			Action:  db.AuthActionLogin,
			Email:   email,
			Outcome: db.AuthOutcomeFailed,
		})
		if err != nil {
			t.Fatalf("failed to seed failed auth attempt: %v", err)
		}
	}

	rec := performJsonRequest(deps.login, http.MethodPost, "/login", map[string]string{
		"email":    email,
		"password": "example-password",
	})

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "try again later" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "try again later")
	}

	count, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("got error %v when getting session count", err)
	}

	if count != 0 {
		t.Fatalf("got number of sessions for user %v wanted %v", count, 0)
	}

	var attemptsAfter int
	err = deps.pool.QueryRow(ctx, "SELECT COUNT(*) FROM auth_attempts WHERE email = $1", email).Scan(&attemptsAfter)
	if err != nil {
		t.Fatalf("failed to count auth attempts after login request: %v", err)
	}

	if attemptsAfter != 10 {
		t.Fatalf("got %d auth attempts after rate limited login, want %d", attemptsAfter, 10)
	}

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "id" {
			t.Fatal("expected response to not include session cookie id")
		}
	}
}

func testLogInSucceedsWhenOneFailedAttemptIsOlderThanWindow(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()
	email := "rate-limit-window@example.com"
	password := "example-password"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	for range 10 {
		err = deps.queries.CreateLoginAuthAttempt(ctx, db.CreateLoginAuthAttemptParams{
			Action:  db.AuthActionLogin,
			Email:   email,
			Outcome: db.AuthOutcomeFailed,
		})
		if err != nil {
			t.Fatalf("failed to seed failed auth attempt: %v", err)
		}
	}

	_, err = deps.pool.Exec(ctx, `
		UPDATE auth_attempts
		SET created_at = NOW() - INTERVAL '11 minutes'
		WHERE id IN (
			SELECT id
			FROM auth_attempts
			WHERE action = $1 AND email = $2 AND outcome = $3
			LIMIT 1
		)
	`, db.AuthActionLogin, email, db.AuthOutcomeFailed)
	if err != nil {
		t.Fatalf("failed to age one failed auth attempt outside rate-limit window: %v", err)
	}

	rec := performJsonRequest(deps.login, http.MethodPost, "/login", map[string]string{
		"email":    email,
		"password": password,
	})

	if rec.Code != http.StatusNoContent {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusNoContent)
	}

	count, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("got error %v when getting session count", err)
	}

	if count != 1 {
		t.Fatalf("got number of sessions for user %v wanted %v", count, 1)
	}

	totalAttempts := countAuthAttemptsByEmail(t, deps.pool, email)
	if totalAttempts != 11 {
		t.Fatalf("got %d total auth attempts for user %q, want %d", totalAttempts, email, 11)
	}

	failedCount := countAuthAttemptsByEmailAndOutcome(t, deps.pool, email, db.AuthOutcomeFailed)
	if failedCount != 10 {
		t.Fatalf("got %d failed auth attempts for user %q, want %d", failedCount, email, 10)
	}

	succeededCount := countAuthAttemptsByEmailAndOutcome(t, deps.pool, email, db.AuthOutcomeSucceeded)
	if succeededCount != 1 {
		t.Fatalf("got %d successful auth attempts for user %q, want %d", succeededCount, email, 1)
	}

	assertSessionCookieExists(t, rec)
}

func testAuthenticatedPasswordResetSucceeds(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-authenticated@example.com"
	currentPassword := "current-password-12345"
	newPassword := "new-password-12345"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: currentPassword,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	var requestSession session.Session
	for range 3 {
		requestSession, err = deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
		if err != nil {
			t.Fatalf("failed to create active session: %v", err)
		}
	}

	authenticatedResetHandler := middleware.CreateSessionMiddleware(deps.userService, deps.sessionService, handlers.CreateAuthenticatedPasswordResetHandler(deps.userService))

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    base64.StdEncoding.EncodeToString(requestSession.DBSession().ID),
		Expires:  requestSession.GetAbsoluteExpiration(),
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	rec := performJsonRequest(authenticatedResetHandler, http.MethodPost, "/user/password", map[string]string{
		"password":    currentPassword,
		"newPassword": newPassword,
	}, &sessionCookie)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusNoContent)
	}

	foundClearedCookie := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "id" {
			foundClearedCookie = true
			if cookie.Value != "" {
				t.Fatalf("expected cleared session cookie value, got %q", cookie.Value)
			}
			if cookie.MaxAge != -1 {
				t.Fatalf("expected cleared session cookie max age -1, got %d", cookie.MaxAge)
			}
		}
	}

	if !foundClearedCookie {
		t.Fatal("expected handler to clear session cookie")
	}

	storedUser, err := deps.queries.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("failed to fetch user after password reset: %v", err)
	}

	newPasswordMatches, err := argon2.VerifyEncoded([]byte(newPassword), []byte(storedUser.PasswordHash))
	if err != nil {
		t.Fatalf("VerifyEncoded returned error for new password: %v", err)
	}
	if !newPasswordMatches {
		t.Fatal("stored password hash does not match new password")
	}

	activeCountAfter, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to get active session count after reset: %v", err)
	}
	if activeCountAfter != 0 {
		t.Fatalf("got %d active sessions after reset, want 0", activeCountAfter)
	}
}

func testAuthenticatedPasswordResetFailsWithWrongPassword(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-authenticated-fails@example.com"
	currentPassword := "current-password-12345"
	incorrectPassword := "incorrect-password-12345"
	newPassword := "new-password-12345"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: currentPassword,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	requestSession, err := deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create active session: %v", err)
	}

	authenticatedResetHandler := middleware.CreateSessionMiddleware(deps.userService, deps.sessionService, handlers.CreateAuthenticatedPasswordResetHandler(deps.userService))

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    base64.StdEncoding.EncodeToString(requestSession.DBSession().ID),
		Expires:  requestSession.GetAbsoluteExpiration(),
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	rec := performJsonRequest(authenticatedResetHandler, http.MethodPost, "/user/password", map[string]string{
		"password":    incorrectPassword,
		"newPassword": newPassword,
	}, &sessionCookie)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "authentication failed" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "authentication failed")
	}

	// NOTE:
	// response recorder only records cookies added by response
	// so when server makes no changes we're good to go...
	assertNoSessionCookie(t, rec)

	storedUser, err := deps.queries.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("failed to fetch user after failed password reset: %v", err)
	}
	if storedUser.PasswordHash != createdUser.DBUser().PasswordHash {
		t.Fatal("stored password hash changed after failed password reset")
	}

	// get session count is active sessions!
	activeCountAfter, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to get active session count after reset: %v", err)
	}
	if activeCountAfter != 1 {
		t.Fatalf("got %d active sessions after reset, want 1", activeCountAfter)
	}
}

func testAuthenticatedPasswordResetFailsWithWeakPassword(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-authenticated-weak@example.com"
	currentPassword := "current-password-12345"
	commonNewPassword := "123456789101112"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: currentPassword,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	requestSession, err := deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create active session: %v", err)
	}

	authenticatedResetHandler := middleware.CreateSessionMiddleware(deps.userService, deps.sessionService, handlers.CreateAuthenticatedPasswordResetHandler(deps.userService))

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    base64.StdEncoding.EncodeToString(requestSession.DBSession().ID),
		Expires:  requestSession.GetAbsoluteExpiration(),
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	rec := performJsonRequest(authenticatedResetHandler, http.MethodPost, "/user/password", map[string]string{
		"password":    currentPassword,
		"newPassword": commonNewPassword,
	}, &sessionCookie)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Password != "password too common" {
		t.Fatalf("got password error %q, want %q", gotErr.Password, "password too common")
	}

	assertNoSessionCookie(t, rec)

	storedUser, err := deps.queries.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("failed to fetch user after failed password reset: %v", err)
	}
	if storedUser.PasswordHash != createdUser.DBUser().PasswordHash {
		t.Fatal("stored password hash changed after failed password reset")
	}

	activeCountAfter, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to get active session count after reset: %v", err)
	}
	if activeCountAfter != 1 {
		t.Fatalf("got %d active sessions after reset, want 1", activeCountAfter)
	}
}

func testCanCreatePasswordResetRequest(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-request@example.com"
	password := "original-password-12345"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	rec := performJsonRequest(deps.passwordReset, http.MethodPost, "/password-reset", map[string]string{
		"email": email,
	})

	if rec.Code != http.StatusNoContent {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusNoContent)
	}

	resetRequestCount := countPasswordResetRequestsByUserID(t, deps.pool, createdUser.DBUser().ID)
	if resetRequestCount != 1 {
		t.Fatalf("got %d password reset requests for user %v, want %d", resetRequestCount, createdUser.DBUser().ID, 1)
	}

	succeededCount := countAuthAttemptsByEmailAndOutcome(t, deps.pool, email, db.AuthOutcomeSucceeded)
	if succeededCount != 1 {
		t.Fatalf("got %d successful auth attempts for user %q, want %d", succeededCount, email, 1)
	}

	if len(deps.emailService.Emails) != 1 {
		t.Fatalf("got %d sent emails, want %d", len(deps.emailService.Emails), 1)
	}

	sentEmail := deps.emailService.Emails[0]
	if sentEmail.ToEmail != email {
		t.Fatalf("got sent email to %q, want %q", sentEmail.ToEmail, email)
	}

	if sentEmail.Subject != "Password Reset" {
		t.Fatalf("got sent email subject %q, want %q", sentEmail.Subject, "Password Reset")
	}

	if !strings.Contains(sentEmail.Body, "?token=") {
		t.Fatalf("expected sent email body to contain token query parameter, got %q", sentEmail.Body)
	}
}

func testCreatingPasswordResetRequestForUnknownUserReturns204(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	email := "missing-password-reset@example.com"

	rec := performJsonRequest(deps.passwordReset, http.MethodPost, "/password-reset", map[string]string{
		"email": email,
	})

	if rec.Code != http.StatusNoContent {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusNoContent)
	}

	resetRequestCount := countPasswordResetRequests(t, deps.pool)
	if resetRequestCount != 0 {
		t.Fatalf("got %d password reset requests, want 0", resetRequestCount)
	}

	attemptCount := countAuthAttemptsByEmail(t, deps.pool, email)
	if attemptCount != 1 {
		t.Fatalf("got %d auth attempts for email %q, want 1", attemptCount, email)
	}
}

func testCreatingThreePasswordResetsIn15MinutesShowsRateLimitError(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-rate-limit-short@example.com"
	password := "original-password-12345"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	firstSeedID := sha256.Sum256([]byte("seeded-reset-request-1"))
	secondSeedID := sha256.Sum256([]byte("seeded-reset-request-2"))

	_, err = deps.queries.CreatePasswordResetRequest(ctx, db.CreatePasswordResetRequestParams{ID: firstSeedID[:], UserID: createdUser.DBUser().ID})
	if err != nil {
		t.Fatalf("failed to seed first password reset request: %v", err)
	}

	_, err = deps.queries.CreatePasswordResetRequest(ctx, db.CreatePasswordResetRequestParams{ID: secondSeedID[:], UserID: createdUser.DBUser().ID})
	if err != nil {
		t.Fatalf("failed to seed second password reset request: %v", err)
	}

	err = deps.queries.CreateLoginAuthAttempt(ctx, db.CreateLoginAuthAttemptParams{
		Action:  db.AuthActionPasswordReset,
		Email:   email,
		Outcome: db.AuthOutcomeSucceeded,
	})
	if err != nil {
		t.Fatalf("failed to seed first successful password reset auth attempt: %v", err)
	}

	err = deps.queries.CreateLoginAuthAttempt(ctx, db.CreateLoginAuthAttemptParams{
		Action:  db.AuthActionPasswordReset,
		Email:   email,
		Outcome: db.AuthOutcomeSucceeded,
	})
	if err != nil {
		t.Fatalf("failed to seed second successful password reset auth attempt: %v", err)
	}

	rec := performJsonRequest(deps.passwordReset, http.MethodPost, "/password-reset", map[string]string{
		"email": email,
	})

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "try again later" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "try again later")
	}

	resetRequestCount := countPasswordResetRequestsByUserID(t, deps.pool, createdUser.DBUser().ID)
	if resetRequestCount != 2 {
		t.Fatalf("got %d password reset requests for user %v, want %d", resetRequestCount, createdUser.DBUser().ID, 2)
	}

	attemptCount := countAuthAttemptsByEmail(t, deps.pool, email)
	if attemptCount != 2 {
		t.Fatalf("got %d auth attempts for email %q, want %d", attemptCount, email, 2)
	}
}

func testCreatingFourPasswordResetsInTwoHoursShowsRateLimitError(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-rate-limit-long@example.com"
	password := "original-password-12345"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	firstSeedID := sha256.Sum256([]byte("seeded-reset-request-long-1"))
	secondSeedID := sha256.Sum256([]byte("seeded-reset-request-long-2"))
	thirdSeedID := sha256.Sum256([]byte("seeded-reset-request-long-3"))

	_, err = deps.queries.CreatePasswordResetRequest(ctx, db.CreatePasswordResetRequestParams{ID: firstSeedID[:], UserID: createdUser.DBUser().ID})
	if err != nil {
		t.Fatalf("failed to seed first password reset request: %v", err)
	}

	_, err = deps.queries.CreatePasswordResetRequest(ctx, db.CreatePasswordResetRequestParams{ID: secondSeedID[:], UserID: createdUser.DBUser().ID})
	if err != nil {
		t.Fatalf("failed to seed second password reset request: %v", err)
	}

	_, err = deps.queries.CreatePasswordResetRequest(ctx, db.CreatePasswordResetRequestParams{ID: thirdSeedID[:], UserID: createdUser.DBUser().ID})
	if err != nil {
		t.Fatalf("failed to seed third password reset request: %v", err)
	}

	err = deps.queries.CreateLoginAuthAttempt(ctx, db.CreateLoginAuthAttemptParams{
		Action:  db.AuthActionPasswordReset,
		Email:   email,
		Outcome: db.AuthOutcomeSucceeded,
	})
	if err != nil {
		t.Fatalf("failed to seed first successful password reset auth attempt: %v", err)
	}

	err = deps.queries.CreateLoginAuthAttempt(ctx, db.CreateLoginAuthAttemptParams{
		Action:  db.AuthActionPasswordReset,
		Email:   email,
		Outcome: db.AuthOutcomeSucceeded,
	})
	if err != nil {
		t.Fatalf("failed to seed second successful password reset auth attempt: %v", err)
	}

	err = deps.queries.CreateLoginAuthAttempt(ctx, db.CreateLoginAuthAttemptParams{
		Action:  db.AuthActionPasswordReset,
		Email:   email,
		Outcome: db.AuthOutcomeSucceeded,
	})
	if err != nil {
		t.Fatalf("failed to seed third successful password reset auth attempt: %v", err)
	}

	seededCreatedAt := time.Now().Add(-20 * time.Minute)
	updateAuthAttemptsCreatedAtForEmailAndActionAndOutcome(t, deps.pool, email, db.AuthActionPasswordReset, db.AuthOutcomeSucceeded, seededCreatedAt)
	updatePasswordResetReqCreatedAtForUserID(t, deps.pool, createdUser.DBUser().ID, seededCreatedAt)

	rec := performJsonRequest(deps.passwordReset, http.MethodPost, "/password-reset", map[string]string{
		"email": email,
	})

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "try again later" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "try again later")
	}

	resetRequestCount := countPasswordResetRequestsByUserID(t, deps.pool, createdUser.DBUser().ID)
	if resetRequestCount != 3 {
		t.Fatalf("got %d password reset requests for user %v, want %d", resetRequestCount, createdUser.DBUser().ID, 3)
	}

	attemptCount := countAuthAttemptsByEmail(t, deps.pool, email)
	if attemptCount != 3 {
		t.Fatalf("got %d auth attempts for email %q, want %d", attemptCount, email, 3)
	}
}

func testPasswordResetSucceedsWithValidResetTokenAndDeactivatesSessions(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-valid-token@example.com"
	currentPassword := "current-password-12345"
	newPassword := "new-password-12345"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: currentPassword,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	_, err = deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create first active session: %v", err)
	}

	_, err = deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create second active session: %v", err)
	}

	err = deps.userService.CreatePasswordResetRequest(ctx, user.CreatePasswordResetRequestBody{Email: email})
	if err != nil {
		t.Fatalf("CreatePasswordResetRequest returned error: %v", err)
	}

	if len(deps.emailService.Emails) != 1 {
		t.Fatalf("got %d sent emails, want %d", len(deps.emailService.Emails), 1)
	}
	resetToken := extractTokenFromResetBody(deps.emailService.Emails[0].Body)
	if resetToken == "" {
		t.Fatalf("failed to extract reset token from email body %q", deps.emailService.Emails[0].Body)
	}

	rec := performJsonRequest(deps.tokenReset, http.MethodPut, "/password-reset?token="+resetToken, map[string]string{
		"newPassword": newPassword,
	})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusNoContent)
	}

	userAfterPassReset, err := deps.queries.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("failed to fetch user after token reset: %v", err)
	}

	newPasswordMatches, err := argon2.VerifyEncoded([]byte(newPassword), []byte(userAfterPassReset.PasswordHash))
	if err != nil {
		t.Fatalf("VerifyEncoded returned error for new password: %v", err)
	}
	if !newPasswordMatches {
		t.Fatal("stored password hash does not match new password")
	}

	activeCountAfter, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to get active session count after token reset: %v", err)
	}
	if activeCountAfter != 0 {
		t.Fatalf("got %d active sessions after token reset, want 0", activeCountAfter)
	}

	rawToken, err := base64.RawURLEncoding.DecodeString(resetToken)
	if err != nil {
		t.Fatalf("failed to decode reset token for post-reset verification: %v", err)
	}
	tokenHash := sha256.Sum256(rawToken)
	_, err = deps.queries.ConsumePasswordResetRequest(ctx, tokenHash[:])
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected consumed reset token to be deleted, got err: %v", err)
	}
}

func testCantResetPasswordWithIncorrectToken(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-incorrect-token@example.com"
	currentPassword := "current-password-12345"
	newPassword := "new-password-12345"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: currentPassword,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	_, err = deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create first active session: %v", err)
	}

	err = deps.userService.CreatePasswordResetRequest(ctx, user.CreatePasswordResetRequestBody{Email: email})
	if err != nil {
		t.Fatalf("CreatePasswordResetRequest returned error: %v", err)
	}

	rec := performJsonRequest(deps.tokenReset, http.MethodPut, "/password-reset?token=incorrect-reset-token", map[string]string{
		"newPassword": newPassword,
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "invalid or expired reset token" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "invalid or expired reset token")
	}

	assertNoSessionCookie(t, rec)

	storedUser, err := deps.queries.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("failed to fetch user after failed token reset: %v", err)
	}
	if storedUser.PasswordHash != createdUser.DBUser().PasswordHash {
		t.Fatal("stored password hash changed after failed token reset")
	}

	activeCountAfter, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to get active session count after failed token reset: %v", err)
	}
	if activeCountAfter != 1 {
		t.Fatalf("got %d active sessions after failed token reset, want %d", activeCountAfter, 1)
	}

	resetRequestCountAfter := countPasswordResetRequestsByUserID(t, deps.pool, createdUser.DBUser().ID)
	if resetRequestCountAfter != 1 {
		t.Fatalf("got %d password reset requests after failed token reset, want %d", resetRequestCountAfter, 1)
	}
}

func testCantResetPasswordWithAlreadyUsedToken(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-used-token@example.com"
	currentPassword := "current-password-12345"
	firstNewPassword := "first-new-password-12345"
	secondNewPassword := "second-new-password-12345"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: currentPassword,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	err = deps.userService.CreatePasswordResetRequest(ctx, user.CreatePasswordResetRequestBody{Email: email})
	if err != nil {
		t.Fatalf("CreatePasswordResetRequest returned error: %v", err)
	}

	resetToken := extractTokenFromResetBody(deps.emailService.Emails[0].Body)
	if resetToken == "" {
		t.Fatalf("failed to extract reset token from email body %q", deps.emailService.Emails[0].Body)
	}

	err = deps.userService.ResetPasswordFromResetRequest(ctx, resetToken, user.ResetPasswordFromResetRequestBody{
		NewPassword: firstNewPassword,
	})
	if err != nil {
		t.Fatalf("ResetPasswordFromResetRequest returned error on first use: %v", err)
	}

	_, err = deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create first active session: %v", err)
	}

	rec := performJsonRequest(deps.tokenReset, http.MethodPut, "/password-reset?token="+resetToken, map[string]string{
		"newPassword": secondNewPassword,
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "invalid or expired reset token" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "invalid or expired reset token")
	}

	activeSessionCount, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("got error when getting session count %v", err)
	}

	if activeSessionCount != 1 {
		t.Fatalf("got active session count %d, want %d", activeSessionCount, 1)
	}
}

func setupUserIntegrationDeps(t *testing.T) userIntegrationDeps {
	t.Helper()

	pool := getIntegrationTestPool(t)

	t.Cleanup(func() {
		cleanupIntegrationTables(t, pool)
	})

	queries := db.New(pool)
	sliceEmailService := &email.SliceEmailService{}
	txnGenerator := user.CreateUserServiceTxnGenerator(pool, queries)
	sessionService := session.NewService(queries)
	userService := user.NewService(queries, txnGenerator, sliceEmailService, sessionService, user.Config{PasswordResetURL: "http://example.com/password-reset"})

	return userIntegrationDeps{
		pool:           pool,
		queries:        queries,
		userService:    userService,
		sessionService: sessionService,
		emailService:   sliceEmailService,
		signUp:         handlers.CreateSignUpHandler(userService, sessionService),
		login:          handlers.CreateLoginHandler(userService, sessionService),
		passwordReset:  handlers.CreatePasswordResetRequestHandler(userService),
		tokenReset:     handlers.CreateTokenPasswordResetHandler(userService),
	}
}

type apiErrorResponse struct {
	Error    string `json:"error"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func decodeErrorResponse(t *testing.T, rec *httptest.ResponseRecorder) apiErrorResponse {
	t.Helper()

	var got apiErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	return got
}

func assertSessionCookieExists(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "id" {
			if cookie.Value == "" {
				t.Fatal("session cookie id has empty value")
			}

			if cookie.Expires.Before(time.Now()) {
				t.Fatalf("Expected session cookie to expire after now, but got %v", cookie.Expires)
			}
			return
		}
	}

	t.Fatal("expected response to include session cookie id")
}

func assertNoSessionCookie(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "id" {
			t.Fatal("expected response to not include session cookie id")
		}
	}
}

func assertNoUserWithEmail(t *testing.T, queries *db.Queries, email string) {
	t.Helper()

	_, err := queries.GetUserByEmail(context.Background(), email)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected no user with email %q, got err %v", email, err)
	}
}

func countUsersByEmail(t *testing.T, pool *pgxpool.Pool, email string) int {
	t.Helper()

	var count int
	err := pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM users WHERE email = $1", email).Scan(&count)
	if err != nil {
		t.Fatalf("failed to count users by email: %v", err)
	}

	return count
}

func countUsers(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()

	var count int
	err := pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count users: %v", err)
	}

	return count
}

func countAuthAttemptsByEmail(t *testing.T, pool *pgxpool.Pool, email string) int {
	t.Helper()

	var count int
	err := pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM auth_attempts WHERE email = $1", email).Scan(&count)
	if err != nil {
		t.Fatalf("failed to count auth attempts for email %q: %v", email, err)
	}

	return count
}

func countAuthAttemptsByEmailAndOutcome(t *testing.T, pool *pgxpool.Pool, email string, outcome db.AuthOutcome) int {
	t.Helper()

	var count int
	err := pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM auth_attempts WHERE email = $1 AND outcome = $2", email, outcome).Scan(&count)
	if err != nil {
		t.Fatalf("failed to count auth attempts for email %q and outcome %q: %v", email, outcome, err)
	}

	return count
}

func countPasswordResetRequestsByUserID(t *testing.T, pool *pgxpool.Pool, userID int64) int {
	t.Helper()

	var count int
	err := pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM password_reset_requests WHERE user_id = $1", userID).Scan(&count)
	if err != nil {
		t.Fatalf("failed to count password reset requests for user %v: %v", userID, err)
	}

	return count
}

func countPasswordResetRequests(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()

	var count int
	err := pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM password_reset_requests").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count password reset requests: %v", err)
	}

	return count
}

func updateAuthAttemptsCreatedAtForEmailAndActionAndOutcome(t *testing.T, pool *pgxpool.Pool, email string, action db.AuthAction, outcome db.AuthOutcome, date time.Time) {
	t.Helper()

	tag, err := pool.Exec(context.Background(), "UPDATE auth_attempts SET created_at = $1 WHERE email = $2 AND action = $3 AND outcome = $4", date, email, action, outcome)
	if err != nil {
		t.Fatalf("failed to update auth_attempts created_at for email %q: %v", email, err)
	}

	if tag.RowsAffected() == 0 {
		t.Fatalf("expected to update auth_attempts created_at for email %q, updated 0 rows", email)
	}
}

func updatePasswordResetReqCreatedAtForUserID(t *testing.T, pool *pgxpool.Pool, userID int64, date time.Time) {
	t.Helper()

	tag, err := pool.Exec(context.Background(), "UPDATE password_reset_requests SET created_at = $1 WHERE user_id = $2", date, userID)
	if err != nil {
		t.Fatalf("failed to update password_reset_requests created_at for user %v: %v", userID, err)
	}

	if tag.RowsAffected() == 0 {
		t.Fatalf("expected to update password_reset_requests created_at for user %v, updated 0 rows", userID)
	}
}

func extractTokenFromResetBody(body string) string {
	parts := strings.Split(body, "?token=")
	if len(parts) < 2 {
		return ""
	}

	token := strings.TrimSpace(parts[len(parts)-1])
	if token == "" {
		return ""
	}

	return token
}
