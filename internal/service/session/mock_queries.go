package session

import (
	"context"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5"
)

type MockQueries struct {
	CreateSessionFn                             func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	DeactivateLeastRecentlyUsedSessionForUserFn func(ctx context.Context, userID int64) error
	DeactivateAllSessionsForUserFn              func(ctx context.Context, userID int64) error
	DeactivateSessionFn                         func(ctx context.Context, id []byte) error
	GetActiveSessionFn                          func(ctx context.Context, id []byte) (db.Session, error)
	GetSessionCountByUserFn                     func(ctx context.Context, userID int64) (int64, error)
	UpdateSessionIDAndRefreshedAtFn             func(ctx context.Context, arg db.UpdateSessionIDAndRefreshedAtParams) (db.Session, error)
	UpdateSessionLastSeenToNowFn                func(ctx context.Context, id []byte) (db.Session, error)
}

func (q *MockQueries) CreateSession(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
	if q.CreateSessionFn != nil {
		return q.CreateSessionFn(ctx, arg)
	}

	return db.Session{ID: arg.ID, UserID: arg.UserID}, nil
}

func (q *MockQueries) DeactivateSession(ctx context.Context, id []byte) error {
	if q.DeactivateSessionFn != nil {
		return q.DeactivateSessionFn(ctx, id)
	}

	return nil
}

func (q *MockQueries) DeactivateLeastRecentlyUsedSessionForUser(ctx context.Context, userID int64) error {
	if q.DeactivateLeastRecentlyUsedSessionForUserFn != nil {
		return q.DeactivateLeastRecentlyUsedSessionForUserFn(ctx, userID)
	}

	return nil
}

func (q *MockQueries) DeactivateAllSessionsForUser(ctx context.Context, userID int64) error {
	if q.DeactivateAllSessionsForUserFn != nil {
		return q.DeactivateAllSessionsForUserFn(ctx, userID)
	}

	return nil
}

func (q *MockQueries) GetActiveSession(ctx context.Context, id []byte) (db.Session, error) {
	if q.GetActiveSessionFn != nil {
		return q.GetActiveSessionFn(ctx, id)
	}

	return db.Session{}, pgx.ErrNoRows
}

func (q *MockQueries) GetSessionCountByUser(ctx context.Context, userID int64) (int64, error) {
	if q.GetSessionCountByUserFn != nil {
		return q.GetSessionCountByUserFn(ctx, userID)
	}

	return 0, nil
}

func (q *MockQueries) UpdateSessionIDAndRefreshedAt(ctx context.Context, arg db.UpdateSessionIDAndRefreshedAtParams) (db.Session, error) {
	if q.UpdateSessionIDAndRefreshedAtFn != nil {
		return q.UpdateSessionIDAndRefreshedAtFn(ctx, arg)
	}

	return db.Session{ID: arg.ID_2}, nil
}

func (q *MockQueries) UpdateSessionLastSeenToNow(ctx context.Context, id []byte) (db.Session, error) {
	if q.UpdateSessionLastSeenToNowFn != nil {
		return q.UpdateSessionLastSeenToNowFn(ctx, id)
	}

	return db.Session{ID: id}, nil
}
