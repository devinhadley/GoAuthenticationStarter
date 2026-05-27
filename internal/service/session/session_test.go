package session

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestCreateSession(t *testing.T) {
	t.Run("can create a session", testCreateValidSession)
	t.Run("returns user not found for sessions user fk violation", testCreateSessionReturnsUserNotFound)
	t.Run("returns session count error", testCreateSessionReturnsSessionCountError)
	t.Run("returns delete least recently used session error", testCreateSessionReturnsDeleteLeastRecentlyUsedSessionError)
	t.Run("returns create session error", testCreateSessionReturnsCreateSessionError)
	t.Run("deactivates oldest session when count is greater than ten", testCreateSessionDeletesOldestWhenSessionCountExceedsLimit)
}

func TestRotateSession(t *testing.T) {
	t.Run("rotates session id", testRotateSession)
	t.Run("returns session not found when session is missing", testRotateSessionReturnsSessionNotFound)
	t.Run("returns update error", testRotateSessionReturnsUpdateError)
}

func TestIsSessionExpired(t *testing.T) {
	t.Run("returns false for active session", testIsSessionExpiredFalseForActiveSession)
	t.Run("returns true for absolute expiration", testIsSessionExpiredTrueForAbsoluteExpiration)
	t.Run("returns true for idle expiration", testIsSessionExpiredTrueForIdleExpiration)
}

func TestShouldRotateSession(t *testing.T) {
	t.Run("returns true when rotation is required", testShouldRotateSessionTrue)
	t.Run("returns false when rotation not required", testShouldRotateSessionFalse)
}

func TestUpdateLastSeen(t *testing.T) {
	t.Run("does not update when threshold has not elapsed", testUpdateLastSeenDoesNotUpdateBeforeThreshold)
	t.Run("updates last seen when threshold has elapsed", testUpdateLastSeenUpdatesAfterThreshold)
	t.Run("returns update error when threshold has elapsed", testUpdateLastSeenReturnsUpdateError)
}

func TestGetSession(t *testing.T) {
	t.Run("returns get session error", testGetSessionReturnsError)
}

func TestExpireSession(t *testing.T) {
	t.Run("returns expire session error", testExpireSessionReturnsError)
}

func testCreateValidSession(t *testing.T) {
	ctx := context.Background()
	userID := int64(1)

	var createSessionArg db.CreateSessionParams

	sessionService := NewService(&mockQueries{
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			createSessionArg = arg

			if arg.UserID != userID {
				t.Fatalf("CreateSession got user id %v, want %v", arg.UserID, userID)
			}

			if len(arg.ID) != 16 {
				t.Fatalf("CreateSession got id length %d, want %d", len(arg.ID), 16)
			}

			return db.Session{
				ID:     arg.ID,
				UserID: arg.UserID,
			}, nil
		},
		DeactivateLeastRecentlyUsedSessionForUserFn: func(ctx context.Context, userID int64) error {
			t.Fatalf("delete last recently used should not be called.")
			return nil
		},
	})

	session, err := sessionService.CreateSession(ctx, userID)
	if err != nil {
		t.Fatalf("CreateSession returned error: %v", err)
	}

	rawSession := session.DBSession()

	if rawSession.UserID != userID {
		t.Fatalf("got user id %v, want %v", rawSession.UserID, userID)
	}

	if len(rawSession.ID) != 16 {
		t.Fatalf("got id length %d, want %d", len(rawSession.ID), 16)
	}

	if !bytes.Equal(rawSession.ID, createSessionArg.ID) {
		t.Fatal("returned session id does not match id passed to CreateSession")
	}
}

func testCreateSessionReturnsUserNotFound(t *testing.T) {
	ctx := context.Background()
	userID := int64(999)

	sessionService := NewService(&mockQueries{
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			return db.Session{}, &pgconn.PgError{
				Code:           "23503",
				ConstraintName: "sessions_user_id_fkey",
			}
		},
	})

	_, err := sessionService.CreateSession(ctx, userID)
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("got error %v, want %v", err, ErrUserNotFound)
	}
}

func testCreateSessionReturnsSessionCountError(t *testing.T) {
	ctx := context.Background()
	userID := int64(99)
	wantErr := errors.New("failed to get session count")

	sessionService := NewService(&mockQueries{
		GetSessionCountByUserFn: func(ctx context.Context, userID int64) (int64, error) {
			return 0, wantErr
		},
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			t.Fatal("CreateSession should not be called when getting session count fails")
			return db.Session{}, nil
		},
	})

	_, err := sessionService.CreateSession(ctx, userID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testCreateSessionReturnsDeleteLeastRecentlyUsedSessionError(t *testing.T) {
	ctx := context.Background()
	userID := int64(42)
	wantErr := errors.New("failed to delete least recently used session")

	sessionService := NewService(&mockQueries{
		GetSessionCountByUserFn: func(ctx context.Context, userID int64) (int64, error) {
			return MaxNumberOfActiveSessions, nil
		},
		DeactivateLeastRecentlyUsedSessionForUserFn: func(ctx context.Context, userID int64) error {
			return wantErr
		},
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			t.Fatal("CreateSession should not be called when deleting least recently used session fails")
			return db.Session{}, nil
		},
	})

	_, err := sessionService.CreateSession(ctx, userID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testCreateSessionReturnsCreateSessionError(t *testing.T) {
	ctx := context.Background()
	userID := int64(7)
	wantErr := errors.New("failed to create session")

	sessionService := NewService(&mockQueries{
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			return db.Session{}, wantErr
		},
	})

	_, err := sessionService.CreateSession(ctx, userID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testCreateSessionDeletesOldestWhenSessionCountExceedsLimit(t *testing.T) {
	ctx := context.Background()
	userID := int64(42)

	deleteOldestCalled := false

	sessionService := NewService(&mockQueries{
		GetSessionCountByUserFn: func(ctx context.Context, gotUserID int64) (int64, error) {
			if gotUserID != userID {
				t.Fatalf("GetSessionCountByUser got user id %v, want %v", gotUserID, userID)
			}

			return 11, nil
		},
		DeactivateLeastRecentlyUsedSessionForUserFn: func(ctx context.Context, gotUserID int64) error {
			deleteOldestCalled = true

			if gotUserID != userID {
				t.Fatalf("DeleteLeastRecentlyUsedSessionByUser got user id %v, want %v", gotUserID, userID)
			}

			return nil
		},
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			if !deleteOldestCalled {
				t.Fatal("DeleteLeastRecentlyUsedSessionByUser should be called before CreateSession")
			}

			return db.Session{ID: arg.ID, UserID: arg.UserID}, nil
		},
	})

	_, err := sessionService.CreateSession(ctx, userID)
	if err != nil {
		t.Fatalf("CreateSession returned error: %v", err)
	}

	if !deleteOldestCalled {
		t.Fatal("DeleteLeastRecentlyUsedSessionByUser was not called")
	}
}

func testRotateSession(t *testing.T) {
	ctx := context.Background()
	originalID := []byte("current-session-id")

	var updateSessionIDArg db.UpdateSessionIDAndRefreshedAtParams

	sessionService := NewService(&mockQueries{
		UpdateSessionIDAndRefreshedAtFn: func(ctx context.Context, arg db.UpdateSessionIDAndRefreshedAtParams) (db.Session, error) {
			updateSessionIDArg = arg

			if !bytes.Equal(arg.ID, originalID) {
				t.Fatalf("UpdateSessionIDByID got id %v, want %v", arg.ID, originalID)
			}

			if len(arg.ID_2) != 16 {
				t.Fatalf("UpdateSessionIDByID got rotated id length %d, want %d", len(arg.ID_2), 16)
			}

			return db.Session{ID: arg.ID_2}, nil
		},
	})

	updatedSessionResult, err := sessionService.RotateSession(ctx, originalID)
	if err != nil {
		t.Fatalf("RotateSession returned error: %v", err)
	}

	rawUpdatedSession := updatedSessionResult.DBSession()

	if len(rawUpdatedSession.ID) != 16 {
		t.Fatalf("got rotated id length %d, want %d", len(rawUpdatedSession.ID), 16)
	}

	if !bytes.Equal(rawUpdatedSession.ID, updateSessionIDArg.ID_2) {
		t.Fatal("returned rotated session id does not match id passed to UpdateSessionIDByID")
	}

	if bytes.Equal(rawUpdatedSession.ID, originalID) {
		t.Fatal("original id matches rotated session id.")
	}
}

func testRotateSessionReturnsUpdateError(t *testing.T) {
	ctx := context.Background()
	originalID := []byte("current-session-id")
	wantErr := errors.New("failed update")

	sessionService := NewService(&mockQueries{
		UpdateSessionIDAndRefreshedAtFn: func(ctx context.Context, arg db.UpdateSessionIDAndRefreshedAtParams) (db.Session, error) {
			return db.Session{}, wantErr
		},
	})

	_, err := sessionService.RotateSession(ctx, originalID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testRotateSessionReturnsSessionNotFound(t *testing.T) {
	ctx := context.Background()
	originalID := []byte("missing-session-id")

	sessionService := NewService(&mockQueries{
		UpdateSessionIDAndRefreshedAtFn: func(ctx context.Context, arg db.UpdateSessionIDAndRefreshedAtParams) (db.Session, error) {
			return db.Session{}, pgx.ErrNoRows
		},
	})

	_, err := sessionService.RotateSession(ctx, originalID)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("got error %v, want %v", err, ErrSessionNotFound)
	}
}

func testIsSessionExpiredFalseForActiveSession(t *testing.T) {
	session := db.Session{
		CreatedAt:  pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -10), Valid: true},
		LastSeenAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -1), Valid: true},
	}

	if SessionFromDB(session).IsExpired() {
		t.Fatal("expected session to be active")
	}
}

func testIsSessionExpiredTrueForAbsoluteExpiration(t *testing.T) {
	session := db.Session{
		CreatedAt:  pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -91), Valid: true},
		LastSeenAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -1), Valid: true},
	}

	if !SessionFromDB(session).IsExpired() {
		t.Fatal("expected session to be expired by absolute expiration")
	}
}

func testIsSessionExpiredTrueForIdleExpiration(t *testing.T) {
	session := db.Session{
		CreatedAt:  pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -10), Valid: true},
		LastSeenAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -15), Valid: true},
	}

	if !SessionFromDB(session).IsExpired() {
		t.Fatal("expected session to be expired by idle expiration")
	}
}

func testShouldRotateSessionFalse(t *testing.T) {
	session := db.Session{
		LastRefreshedAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -1), Valid: true},
	}

	if SessionFromDB(session).ShouldRotate() {
		t.Fatal("expected session rotation not to be required")
	}
}

func testShouldRotateSessionTrue(t *testing.T) {
	session := db.Session{
		LastRefreshedAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -8), Valid: true},
	}

	if !SessionFromDB(session).ShouldRotate() {
		t.Fatal("expected session rotation to be required")
	}
}

func testUpdateLastSeenDoesNotUpdateBeforeThreshold(t *testing.T) {
	ctx := context.Background()
	updateCalled := false

	sessionService := NewService(&mockQueries{
		UpdateSessionLastSeenToNowFn: func(ctx context.Context, id []byte) (db.Session, error) {
			updateCalled = true
			return db.Session{}, nil
		},
	})

	session := db.Session{
		ID:         []byte("session-id"),
		LastSeenAt: pgtype.Timestamptz{Time: time.Now().Add(-(20 * time.Minute) + time.Second), Valid: true},
	}

	err := sessionService.UpdateLastSeen(ctx, SessionFromDB(session))
	if err != nil {
		t.Fatalf("UpdateLastSeen returned error: %v", err)
	}

	if updateCalled {
		t.Fatal("expected last seen not to be updated before threshold")
	}
}

func testUpdateLastSeenUpdatesAfterThreshold(t *testing.T) {
	ctx := context.Background()

	session := db.Session{
		ID:         []byte("session-id"),
		LastSeenAt: pgtype.Timestamptz{Time: time.Now().Add(-(20 * time.Minute) - time.Second), Valid: true},
	}

	updateCalled := false
	sessionService := NewService(&mockQueries{
		UpdateSessionLastSeenToNowFn: func(callCtx context.Context, id []byte) (db.Session, error) {
			updateCalled = true

			if callCtx != ctx {
				t.Fatal("UpdateSessionLastSeenToNow called with unexpected context")
			}

			if !bytes.Equal(id, session.ID) {
				t.Fatalf("UpdateSessionLastSeenToNow got id %v, want %v", id, session.ID)
			}

			return db.Session{ID: id}, nil
		},
	})

	err := sessionService.UpdateLastSeen(ctx, SessionFromDB(session))
	if err != nil {
		t.Fatalf("UpdateLastSeen returned error: %v", err)
	}

	if !updateCalled {
		t.Fatal("expected last seen to be updated after threshold")
	}
}

func testUpdateLastSeenReturnsUpdateError(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("failed to update last seen")

	session := db.Session{
		ID:         []byte("session-id"),
		LastSeenAt: pgtype.Timestamptz{Time: time.Now().Add(-(20 * time.Minute) - time.Second), Valid: true},
	}

	sessionService := NewService(&mockQueries{
		UpdateSessionLastSeenToNowFn: func(callCtx context.Context, id []byte) (db.Session, error) {
			if callCtx != ctx {
				t.Fatal("UpdateSessionLastSeenToNow called with unexpected context")
			}

			if !bytes.Equal(id, session.ID) {
				t.Fatalf("UpdateSessionLastSeenToNow got id %v, want %v", id, session.ID)
			}

			return db.Session{}, wantErr
		},
	})

	err := sessionService.UpdateLastSeen(ctx, SessionFromDB(session))
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testGetSessionReturnsError(t *testing.T) {
	ctx := context.Background()
	sessionID := []byte("session-id")
	wantErr := errors.New("failed to get session")

	sessionService := NewService(&mockQueries{
		GetActiveSessionFn: func(callCtx context.Context, id []byte) (db.Session, error) {
			if callCtx != ctx {
				t.Fatal("GetSessionByID called with unexpected context")
			}

			if !bytes.Equal(id, sessionID) {
				t.Fatalf("GetSessionByID got id %v, want %v", id, sessionID)
			}

			return db.Session{}, wantErr
		},
	})

	_, err := sessionService.GetSession(ctx, sessionID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testExpireSessionReturnsError(t *testing.T) {
	ctx := context.Background()
	sessionID := []byte("session-id")
	wantErr := errors.New("failed to expire session")

	sessionService := NewService(&mockQueries{
		DeactivateSessionFn: func(callCtx context.Context, id []byte) error {
			if callCtx != ctx {
				t.Fatal("DeleteSessionByID called with unexpected context")
			}

			if !bytes.Equal(id, sessionID) {
				t.Fatalf("DeleteSessionByID got id %v, want %v", id, sessionID)
			}

			return wantErr
		},
	})

	err := sessionService.ExpireSession(ctx, sessionID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

type mockQueries struct {
	CreateSessionFn                             func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	DeactivateLeastRecentlyUsedSessionForUserFn func(ctx context.Context, userID int64) error
	DeactivateAllSessionsForUserFn              func(ctx context.Context, userID int64) error
	DeactivateSessionFn                         func(ctx context.Context, id []byte) error
	GetActiveSessionFn                          func(ctx context.Context, id []byte) (db.Session, error)
	GetSessionCountByUserFn                     func(ctx context.Context, userID int64) (int64, error)
	UpdateSessionIDAndRefreshedAtFn             func(ctx context.Context, arg db.UpdateSessionIDAndRefreshedAtParams) (db.Session, error)
	UpdateSessionLastSeenToNowFn                func(ctx context.Context, id []byte) (db.Session, error)
}

func (q *mockQueries) CreateSession(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
	if q.CreateSessionFn != nil {
		return q.CreateSessionFn(ctx, arg)
	}

	return db.Session{ID: arg.ID, UserID: arg.UserID}, nil
}

func (q *mockQueries) DeactivateSession(ctx context.Context, id []byte) error {
	if q.DeactivateSessionFn != nil {
		return q.DeactivateSessionFn(ctx, id)
	}

	return nil
}

func (q *mockQueries) DeactivateLeastRecentlyUsedSessionForUser(ctx context.Context, userID int64) error {
	if q.DeactivateLeastRecentlyUsedSessionForUserFn != nil {
		return q.DeactivateLeastRecentlyUsedSessionForUserFn(ctx, userID)
	}

	return nil
}

func (q *mockQueries) DeactivateAllSessionsForUser(ctx context.Context, userID int64) error {
	if q.DeactivateAllSessionsForUserFn != nil {
		return q.DeactivateAllSessionsForUserFn(ctx, userID)
	}

	return nil
}

func (q *mockQueries) GetActiveSession(ctx context.Context, id []byte) (db.Session, error) {
	if q.GetActiveSessionFn != nil {
		return q.GetActiveSessionFn(ctx, id)
	}

	return db.Session{}, pgx.ErrNoRows
}

func (q *mockQueries) GetSessionCountByUser(ctx context.Context, userID int64) (int64, error) {
	if q.GetSessionCountByUserFn != nil {
		return q.GetSessionCountByUserFn(ctx, userID)
	}

	return 0, nil
}

func (q *mockQueries) UpdateSessionIDAndRefreshedAt(ctx context.Context, arg db.UpdateSessionIDAndRefreshedAtParams) (db.Session, error) {
	if q.UpdateSessionIDAndRefreshedAtFn != nil {
		return q.UpdateSessionIDAndRefreshedAtFn(ctx, arg)
	}

	return db.Session{ID: arg.ID_2}, nil
}

func (q *mockQueries) UpdateSessionLastSeenToNow(ctx context.Context, id []byte) (db.Session, error) {
	if q.UpdateSessionLastSeenToNowFn != nil {
		return q.UpdateSessionLastSeenToNowFn(ctx, id)
	}

	return db.Session{ID: id}, nil
}
