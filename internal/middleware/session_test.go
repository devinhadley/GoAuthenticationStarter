package middleware

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
	"devinhadley/gobootstrapweb/internal/testutil/mocks"

	"github.com/jackc/pgx/v5/pgtype"
)

// TODO: Lets make

// NOTE: Integration tests should cover main happy paths of session middleware and reasonable errors.
// Middleware unit tests here are useful for difficult to produce errors.

func TestCreateSessionMiddlewareErrorFlows(t *testing.T) {
	t.Run("rotate session error proceeds as best effort", testRotateSessionErrorProceedsBestEffort)
	t.Run("expired session error still clears cookie and continues", testExpiredSessionExpireErrorClearsCookie)
	t.Run("update last seen error still authenticates", testUpdateLastSeenErrorStillAuthenticates)
}

func TestCreateSessionMiddlewareFlowControl(t *testing.T) {
	t.Run("rotation success updates last seen with rotated id", testRotationSuccessUpdatesLastSeenWithRotatedID)
}

func testRotateSessionErrorProceedsBestEffort(t *testing.T) {
	ctx := context.Background()
	originalID := []byte("session-id-123456")
	rotateErr := errors.New("rotate failed")

	updateLastSeenCalled := false
	nextCalled := false

	userService := user.NewService(&mocks.MockUserQueries{
		GetUserByIDFn: func(ctx context.Context, id int64) (db.User, error) {
			return db.User{ID: id, Email: "test@example.com"}, nil
		},
	}, mocks.MockEmailService{}, user.Config{})

	sessionService := session.NewService(&mocks.MockSessionQueries{
		GetActiveSessionFn: func(ctx context.Context, id []byte) (db.Session, error) {
			return db.Session{
				ID:              originalID,
				UserID:          42,
				CreatedAt:       pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -2), Valid: true},
				LastSeenAt:      pgtype.Timestamptz{Time: time.Now().Add(-25 * time.Minute), Valid: true},
				LastRefreshedAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -8), Valid: true},
				IsActive:        true,
			}, nil
		},
		UpdateSessionIDAndRefreshedAtFn: func(ctx context.Context, arg db.UpdateSessionIDAndRefreshedAtParams) (db.Session, error) {
			return db.Session{}, rotateErr
		},
		UpdateSessionLastSeenToNowFn: func(ctx context.Context, id []byte) (db.Session, error) {
			updateLastSeenCalled = true
			if string(id) != string(originalID) {
				t.Fatalf("UpdateSessionLastSeenToNow got id %v, want %v", id, originalID)
			}
			return db.Session{ID: id}, nil
		},
	})

	handler := CreateSessionMiddleware(userService, sessionService, func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		usr, err := UserFromContext(r.Context())
		if err != nil {
			t.Fatalf("expected authenticated user, got error %v", err)
		}
		if usr.DBUser().ID != 42 {
			t.Fatalf("expected user id 42, got %v", usr.DBUser().ID)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: "id", Value: base64.StdEncoding.EncodeToString(originalID)})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
	if !updateLastSeenCalled {
		t.Fatal("expected update last seen to be called")
	}

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "id" {
			t.Fatal("expected no rotated session cookie on rotate failure")
		}
	}
}

func testExpiredSessionExpireErrorClearsCookie(t *testing.T) {
	originalID := []byte("session-id-123456")
	expireErr := errors.New("expire failed")
	nextCalled := false

	userService := user.NewService(&mocks.MockUserQueries{}, mocks.MockEmailService{}, user.Config{})
	sessionService := session.NewService(&mocks.MockSessionQueries{
		GetActiveSessionFn: func(ctx context.Context, id []byte) (db.Session, error) {
			return db.Session{
				ID:              originalID,
				UserID:          42,
				CreatedAt:       pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -91), Valid: true},
				LastSeenAt:      pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -1), Valid: true},
				LastRefreshedAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -8), Valid: true},
				IsActive:        true,
			}, nil
		},
		DeactivateSessionFn: func(ctx context.Context, id []byte) error {
			return expireErr
		},
	})

	handler := CreateSessionMiddleware(userService, sessionService, func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		if _, err := UserFromContext(r.Context()); !errors.Is(err, ErrUserNotInContext) {
			t.Fatalf("expected no user in context, got %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: "id", Value: base64.StdEncoding.EncodeToString(originalID)})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}

	foundClearedCookie := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "id" {
			foundClearedCookie = true
			if cookie.MaxAge != -1 {
				t.Fatalf("expected cleared cookie max age -1, got %d", cookie.MaxAge)
			}
		}
	}
	if !foundClearedCookie {
		t.Fatal("expected session cookie to be cleared")
	}
}

func testUpdateLastSeenErrorStillAuthenticates(t *testing.T) {
	originalID := []byte("session-id-123456")
	updateErr := errors.New("update last seen failed")
	nextCalled := false

	userService := user.NewService(&mocks.MockUserQueries{
		GetUserByIDFn: func(ctx context.Context, id int64) (db.User, error) {
			return db.User{ID: id, Email: "test@example.com"}, nil
		},
	}, mocks.MockEmailService{}, user.Config{})

	sessionService := session.NewService(&mocks.MockSessionQueries{
		GetActiveSessionFn: func(ctx context.Context, id []byte) (db.Session, error) {
			return db.Session{
				ID:              originalID,
				UserID:          42,
				CreatedAt:       pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -2), Valid: true},
				LastSeenAt:      pgtype.Timestamptz{Time: time.Now().Add(-25 * time.Minute), Valid: true},
				LastRefreshedAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -1), Valid: true},
				IsActive:        true,
			}, nil
		},
		UpdateSessionLastSeenToNowFn: func(ctx context.Context, id []byte) (db.Session, error) {
			return db.Session{}, updateErr
		},
	})

	handler := CreateSessionMiddleware(userService, sessionService, func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		usr, err := UserFromContext(r.Context())
		if err != nil {
			t.Fatalf("expected authenticated user, got error %v", err)
		}
		if usr.DBUser().ID != 42 {
			t.Fatalf("expected user id 42, got %v", usr.DBUser().ID)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: "id", Value: base64.StdEncoding.EncodeToString(originalID)})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
}

func testRotationSuccessUpdatesLastSeenWithRotatedID(t *testing.T) {
	originalID := []byte("session-id-123456")
	rotatedID := []byte("rotated-session-1")

	updateLastSeenCalled := false

	userService := user.NewService(&mocks.MockUserQueries{}, mocks.MockEmailService{}, user.Config{})

	sessionService := session.NewService(&mocks.MockSessionQueries{
		GetActiveSessionFn: func(ctx context.Context, id []byte) (db.Session, error) {
			return db.Session{
				ID:              originalID,
				UserID:          42,
				CreatedAt:       pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -2), Valid: true},
				LastSeenAt:      pgtype.Timestamptz{Time: time.Now().Add(-25 * time.Minute), Valid: true},
				LastRefreshedAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -8), Valid: true},
				IsActive:        true,
			}, nil
		},
		UpdateSessionIDAndRefreshedAtFn: func(ctx context.Context, arg db.UpdateSessionIDAndRefreshedAtParams) (db.Session, error) {
			return db.Session{
				ID:              rotatedID,
				UserID:          42,
				CreatedAt:       pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -2), Valid: true},
				LastSeenAt:      pgtype.Timestamptz{Time: time.Now().Add(-25 * time.Minute), Valid: true},
				LastRefreshedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
				IsActive:        true,
			}, nil
		},
		UpdateSessionLastSeenToNowFn: func(ctx context.Context, id []byte) (db.Session, error) {
			updateLastSeenCalled = true
			if string(id) != string(rotatedID) {
				t.Fatalf("UpdateSessionLastSeenToNow got id %v, want %v", id, rotatedID)
			}
			return db.Session{ID: id}, nil
		},
	})

	handler := CreateSessionMiddleware(userService, sessionService, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: "id", Value: base64.StdEncoding.EncodeToString(originalID)})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !updateLastSeenCalled {
		t.Fatal("expected update last seen to be called")
	}
}

func TestCreateGetUserFuncCachesUser(t *testing.T) {
	const userID int64 = 42

	callCount := 0
	wantUser := db.User{ID: userID, Email: "test@example.com"}

	userService := user.NewService(&mocks.MockUserQueries{
		GetUserByIDFn: func(ctx context.Context, id int64) (db.User, error) {
			callCount++
			if id != userID {
				t.Fatalf("GetUserByID got id %v, want %v", id, userID)
			}

			return wantUser, nil
		},
	}, mocks.MockEmailService{}, user.Config{})

	getUser := createGetUserFunc(userID, userService, context.Background())

	gotUserOne, err := getUser()
	if err != nil {
		t.Fatalf("first getUser() returned error: %v", err)
	}

	gotUserTwo, err := getUser()
	if err != nil {
		t.Fatalf("second getUser() returned error: %v", err)
	}

	if gotUserOne.DBUser().ID != wantUser.ID {
		t.Fatalf("first getUser() got id %v, want %v", gotUserOne.DBUser().ID, wantUser.ID)
	}

	if gotUserTwo.DBUser().ID != wantUser.ID {
		t.Fatalf("second getUser() got id %v, want %v", gotUserTwo.DBUser().ID, wantUser.ID)
	}

	if callCount != 1 {
		t.Fatalf("GetUserByID called %v times, want 1", callCount)
	}
}
