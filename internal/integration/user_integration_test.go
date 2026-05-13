// Integration contains all integration tests and helpers. It is one package to streamline shared test dependencies like DB.
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/handlers"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matthewhartstonge/argon2"
)

type userIntegrationDeps struct {
	pool        *pgxpool.Pool
	queries     *db.Queries
	userService *user.Service
	signUp      http.HandlerFunc
	login       http.HandlerFunc
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
	t.Run("returns bad request when user does not exist", testLogInReturnsBadRequestWhenUserDoesNotExist)
	t.Run("returns bad request when password is incorrect and doesnt create session", testLogInReturnsBadRequestWhenPasswordIsIncorrect)
	t.Run("returns 429 when rate limited and doesnt create session / auth attempt", testLogInReturnsTooManyRequestsWhenRateLimited)
	t.Run("login succeeds when one of ten failed attempts is older than ten minutes", testLogInSucceedsWhenOneFailedAttemptIsOlderThanWindow)
	t.Run("test rejects invalid email", testLogInRejectsInvalidEmail)
}

func testSignUpSucceedsAndPersistsUser(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	input := map[string]string{
		"email":    "signup@example.com",
		"password": "example-password",
	}

	rec := performJsonRequest(deps.signUp, http.MethodPost, "/signup", input)
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
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
	if first.Code != http.StatusOK {
		t.Fatalf("first sign up got status %d, want %d", first.Code, http.StatusOK)
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

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	// Session created for the user.
	count, err := deps.queries.GetSessionCountByUser(ctx, user.ID)
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

func testLogInReturnsBadRequestWhenUserDoesNotExist(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	email := "missing@example.com"

	rec := performJsonRequest(deps.login, http.MethodPost, "/login", map[string]string{
		"email":    email,
		"password": "example-password",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
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

func testLogInReturnsBadRequestWhenPasswordIsIncorrect(t *testing.T) {
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

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "authentication failed" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "authentication failed")
	}

	// Session not created for the user.
	count, err := deps.queries.GetSessionCountByUser(ctx, user.ID)
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

	count, err := deps.queries.GetSessionCountByUser(ctx, createdUser.ID)
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

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	count, err := deps.queries.GetSessionCountByUser(ctx, createdUser.ID)
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

func setupUserIntegrationDeps(t *testing.T) userIntegrationDeps {
	t.Helper()

	pool := getIntegrationTestPool(t)

	t.Cleanup(func() {
		cleanupIntegrationTables(t, pool)
	})

	queries := db.New(pool)
	userService := user.NewService(queries)
	sessionService := session.NewService(queries)

	return userIntegrationDeps{
		pool:        pool,
		queries:     queries,
		userService: userService,
		signUp:      handlers.CreateSignUpHandler(userService, sessionService),
		login:       handlers.CreateLoginHandler(userService, sessionService),
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
