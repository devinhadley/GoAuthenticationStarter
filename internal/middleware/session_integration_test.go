package middleware

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
	"devinhadley/gobootstrapweb/internal/utils"
	"devinhadley/gobootstrapweb/internal/utils/testutil"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSessionMiddlewareCanAuthenticateIntegration(t *testing.T) {
	t.Run("valid session makes it so user can be accessed in handler", testValidSessionAuthenticatesCorrectUser)
	t.Run("no session cookie continues to next handler unauthenticated", testNoSessionCookieContinuesUnauthenticated)
	t.Run("malformed base64 session cookie continues unauthenticated", testMalformedSessionCookieContinuesUnauthenticated)
	t.Run("well-formed session id not found continues unauthenticated", testSessionIDNotFoundContinuesUnauthenticated)
}

func TestExpiredSessionIntegration(t *testing.T) {
	t.Run("absolute expired session does not authenticate and deactivates session", testAbsoluteExpiration)
	t.Run("idle expired session does not authenticate and deactivates session", needsImplemented)
	t.Run("expired session clears cookie", needsImplemented)
}

func TestRotateSessionIntegration(t *testing.T) {
	t.Run("session outside rotation threshold rotates and sets new cookie", needsImplemented)
	t.Run("session inside rotation threshold does not rotate", needsImplemented)
	t.Run("rotate session error continues without rotated cookie", needsImplemented)
}

func TestUpdateLastSeenIntegration(t *testing.T) {
	t.Run("update last seen is skipped when threshold not reached", needsImplemented)
	t.Run("update last seen succeeds when threshold reached", needsImplemented)
}

func testValidSessionAuthenticatesCorrectUser(t *testing.T) {
	deps := getTestDependencies(t)

	createdUser, err := deps.userService.SignUp(context.Background(), user.AuthenticateBody{
		Email:    "test@example.com",
		Password: "a-password-!-9999",
	})
	if err != nil {
		t.Fatalf("failed to create test user %v", err)
	}
	session, err := deps.sessionService.CreateSession(context.Background(), createdUser)
	if err != nil {
		t.Fatalf("failed to create test session %v", err)
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		user, err := UserFromContext(r.Context())
		if err != nil {
			t.Fatalf("failed to get user from context %v", err)
		}

		if createdUser.ID != user.ID {
			t.Fatalf("expected user from context to have id %v, got %v", createdUser.ID, user.ID)
		}

		utils.WriteJSONResponse(w, http.StatusOK, map[string]any{"status": "ok"})
	}

	sessionMiddleware := CreateSessionMiddleware(&deps.userService, &deps.sessionService, handler)

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    base64.StdEncoding.EncodeToString(session.DBSession().ID),
		Expires:  session.GetAbsoluteExpiration(),
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	res := testutil.PerformJSONRequest(sessionMiddleware, http.MethodGet, "/test", map[string]any{}, &sessionCookie)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status ok, got %v", res.Code)
	}
}

func testNoSessionCookieContinuesUnauthenticated(t *testing.T) {
	deps := getTestDependencies(t)
	handlerCalled := false

	handler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		_, err := UserFromContext(r.Context())
		if !errors.Is(err, ErrUserNotInContext) {
			t.Fatalf("expected error %v, got %v", ErrUserNotInContext, err)
		}

		utils.WriteJSONResponse(w, http.StatusOK, map[string]any{"status": "ok"})
	}

	sessionMiddleware := CreateSessionMiddleware(&deps.userService, &deps.sessionService, handler)

	res := testutil.PerformJSONRequest(sessionMiddleware, http.MethodGet, "/test", map[string]any{})

	if res.Code != http.StatusOK {
		t.Fatalf("expected status ok, got %v", res.Code)
	}

	if !handlerCalled {
		t.Fatal("expected next handler to be called")
	}
}

func testMalformedSessionCookieContinuesUnauthenticated(t *testing.T) {
	deps := getTestDependencies(t)
	handlerCalled := false

	handler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		_, err := UserFromContext(r.Context())
		if !errors.Is(err, ErrUserNotInContext) {
			t.Fatalf("expected error %v, got %v", ErrUserNotInContext, err)
		}

		utils.WriteJSONResponse(w, http.StatusOK, map[string]any{"status": "ok"})
	}

	sessionMiddleware := CreateSessionMiddleware(&deps.userService, &deps.sessionService, handler)

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    "!!!!",
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	res := testutil.PerformJSONRequest(sessionMiddleware, http.MethodGet, "/test", map[string]any{}, &sessionCookie)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status ok, got %v", res.Code)
	}

	if !handlerCalled {
		t.Fatal("expected next handler to be called")
	}
}

func testSessionIDNotFoundContinuesUnauthenticated(t *testing.T) {
	deps := getTestDependencies(t)
	handlerCalled := false

	handler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		_, err := UserFromContext(r.Context())
		if !errors.Is(err, ErrUserNotInContext) {
			t.Fatalf("expected error %v, got %v", ErrUserNotInContext, err)
		}

		utils.WriteJSONResponse(w, http.StatusOK, map[string]any{"status": "ok"})
	}

	sessionMiddleware := CreateSessionMiddleware(&deps.userService, &deps.sessionService, handler)

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    base64.StdEncoding.EncodeToString([]byte("missing-session!")),
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	res := testutil.PerformJSONRequest(sessionMiddleware, http.MethodGet, "/test", map[string]any{}, &sessionCookie)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status ok, got %v", res.Code)
	}

	if !handlerCalled {
		t.Fatal("expected next handler to be called")
	}
}

func testAbsoluteExpiration(t *testing.T) {
	// Arrange
	deps := getTestDependencies(t)

	// Create user
	createdUser, err := deps.userService.SignUp(context.Background(), user.AuthenticateBody{
		Email:    "test@example.com",
		Password: "a-password-!-9999",
	})
	if err != nil {
		t.Fatalf("failed to create test user %v", err)
	}
	session, err := deps.sessionService.CreateSession(context.Background(), createdUser)
	if err != nil {
		t.Fatalf("failed to create test session %v", err)
	}

	makeSessionAbsolutelyExpired(t, deps, session.DBSession().ID)

	handler := func(w http.ResponseWriter, r *http.Request) {
		user, err := UserFromContext(r.Context())
		if user != (db.User{}) {
			t.Fatalf("wanted empty user but got %v", user)
		}
		if !errors.Is(err, ErrUserNotInContext) {
			t.Fatalf("wanted error %v but got %v", ErrUserNotInContext, err)
		}
		utils.WriteJSONResponse(w, http.StatusOK, map[string]any{"status": "ok"})
	}

	sessionMiddleware := CreateSessionMiddleware(&deps.userService, &deps.sessionService, handler)

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    base64.StdEncoding.EncodeToString(session.DBSession().ID),
		Expires:  session.GetAbsoluteExpiration(), // not testing
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	// Act
	rec := testutil.PerformJSONRequest(sessionMiddleware, http.MethodGet, "/test", map[string]any{}, &sessionCookie)

	// Assert

	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("wanted response status code %v, got %v", http.StatusOK, rec.Result().StatusCode)
	}

	assertSessionExpired(t, deps, session.DBSession().ID)

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
		t.Fatal("expected middleware to clear session cookie")
	}
}

func needsImplemented(t *testing.T) {
	t.Skip("needs implemented")
}

func makeSessionAbsolutelyExpired(t *testing.T, deps sessionIntegrationTestDependencies, sessionId []byte) {
	t.Helper()

	fourMonthsAgo := time.Now().AddDate(0, -4, 0)

	query := `
	UPDATE sessions
	SET created_at = $2
	WHERE id = $1;
	`
	tag, err := deps.pool.Exec(context.Background(), query, sessionId, fourMonthsAgo)
	if err != nil {
		t.Fatalf("failed to make session absolutely expired %v", err)
	}

	if tag.RowsAffected() != 1 {
		t.Fatalf("wanted 1 row affected when expiring session, got %d", tag.RowsAffected())
	}
}

func assertSessionExpired(t *testing.T, deps sessionIntegrationTestDependencies, sessionId []byte) {
	t.Helper()

	query := `
	SELECT is_active
	FROM sessions
	WHERE id = $1;
	`
	row := deps.pool.QueryRow(context.Background(), query, sessionId)

	var isActive bool
	err := row.Scan(&isActive)
	if err != nil {
		t.Fatalf("failed to get session is_active when asserting expired %v", err)
	}

	if isActive {
		t.Fatalf("wanted session is_active %v, got %v", false, isActive)
	}
}

type sessionIntegrationTestDependencies struct {
	userService    user.Service
	sessionService session.Service
	pool           *pgxpool.Pool
	queries        db.Queries
}

func getTestDependencies(t *testing.T) sessionIntegrationTestDependencies {
	dsn := testutil.GetIntegrationTestDSN(t)

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("failed to create database pool: %v", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Fatalf("failed to ping database: %v", err)
	}

	t.Cleanup(func() {
		testutil.CleanupIntegrationTables(t, pool)
		pool.Close()
	})

	queries := db.New(pool)

	return sessionIntegrationTestDependencies{queries: *queries, userService: *user.NewService(queries), sessionService: *session.NewService(queries), pool: pool}
}
