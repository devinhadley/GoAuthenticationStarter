package mocks

import (
	"context"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5"
)

type MockUserQueries struct {
	CreateUserFn                       func(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUserByEmailFn                   func(ctx context.Context, email string) (db.User, error)
	GetUserByIDFn                      func(ctx context.Context, id int64) (db.User, error)
	CountFailedAuthAttemptsSinceFn     func(ctx context.Context, arg db.CountFailedAuthAttemptsSinceParams) (int64, error)
	CountAuthAttemptsForPassResetReqFn func(ctx context.Context, arg db.CountAuthAttemptsForPassResetReqParams) (db.CountAuthAttemptsForPassResetReqRow, error)
	CreateLoginAuthAttemptFn           func(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error
	CreatePasswordResetRequestFn       func(ctx context.Context, arg db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error)
	GetPasswordResetRequestByIDFn      func(ctx context.Context, id []byte) (db.PasswordResetRequest, error)
	DeletePasswordResetRequestByIDFn   func(ctx context.Context, id []byte) error
	UpdatePasswordHashFn               func(ctx context.Context, arg db.UpdatePasswordHashParams) error
	DeactivateAllSessionsForUserFn     func(ctx context.Context, userID int64) error
}

func (q *MockUserQueries) CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
	if q.CreateUserFn != nil {
		return q.CreateUserFn(ctx, arg)
	}

	return db.User{
		ID:           1,
		Email:        arg.Email,
		PasswordHash: arg.PasswordHash,
	}, nil
}

func (q *MockUserQueries) GetUserByEmail(ctx context.Context, email string) (db.User, error) {
	if q.GetUserByEmailFn != nil {
		return q.GetUserByEmailFn(ctx, email)
	}

	return db.User{
		ID:    1,
		Email: email,
	}, nil
}

func (q *MockUserQueries) GetUserByID(ctx context.Context, id int64) (db.User, error) {
	if q.GetUserByIDFn != nil {
		return q.GetUserByIDFn(ctx, id)
	}

	return db.User{
		ID:    id,
		Email: "test@example.com",
	}, nil
}

func (q *MockUserQueries) CountFailedAuthAttemptsSince(ctx context.Context, arg db.CountFailedAuthAttemptsSinceParams) (int64, error) {
	if q.CountFailedAuthAttemptsSinceFn != nil {
		return q.CountFailedAuthAttemptsSinceFn(ctx, arg)
	}
	return 0, nil
}

func (q *MockUserQueries) CountAuthAttemptsForPassResetReq(ctx context.Context, arg db.CountAuthAttemptsForPassResetReqParams) (db.CountAuthAttemptsForPassResetReqRow, error) {
	if q.CountAuthAttemptsForPassResetReqFn != nil {
		return q.CountAuthAttemptsForPassResetReqFn(ctx, arg)
	}

	return db.CountAuthAttemptsForPassResetReqRow{}, nil
}

func (q *MockUserQueries) CreateLoginAuthAttempt(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error {
	if q.CreateLoginAuthAttemptFn != nil {
		return q.CreateLoginAuthAttemptFn(ctx, arg)
	}

	return nil
}

func (q *MockUserQueries) CreatePasswordResetRequest(ctx context.Context, arg db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error) {
	if q.CreatePasswordResetRequestFn != nil {
		return q.CreatePasswordResetRequestFn(ctx, arg)
	}

	return db.PasswordResetRequest{ID: arg.ID, UserID: arg.UserID}, nil
}

func (q *MockUserQueries) GetPasswordResetRequestByID(ctx context.Context, id []byte) (db.PasswordResetRequest, error) {
	if q.GetPasswordResetRequestByIDFn != nil {
		return q.GetPasswordResetRequestByIDFn(ctx, id)
	}

	return db.PasswordResetRequest{}, pgx.ErrNoRows
}

func (q *MockUserQueries) DeletePasswordResetRequestByID(ctx context.Context, id []byte) error {
	if q.DeletePasswordResetRequestByIDFn != nil {
		return q.DeletePasswordResetRequestByIDFn(ctx, id)
	}

	return nil
}

func (q *MockUserQueries) UpdatePasswordHash(ctx context.Context, arg db.UpdatePasswordHashParams) error {
	if q.UpdatePasswordHashFn != nil {
		return q.UpdatePasswordHashFn(ctx, arg)
	}

	return nil
}

func (q *MockUserQueries) DeactivateAllSessionsForUser(ctx context.Context, userID int64) error {
	if q.DeactivateAllSessionsForUserFn != nil {
		return q.DeactivateAllSessionsForUserFn(ctx, userID)
	}

	return nil
}

type MockSessionQueries struct {
	CreateSessionFn                             func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	DeactivateLeastRecentlyUsedSessionForUserFn func(ctx context.Context, userID int64) error
	DeactivateSessionFn                         func(ctx context.Context, id []byte) error
	GetActiveSessionFn                          func(ctx context.Context, id []byte) (db.Session, error)
	GetSessionCountByUserFn                     func(ctx context.Context, userID int64) (int64, error)
	UpdateSessionIDAndRefreshedAtFn             func(ctx context.Context, arg db.UpdateSessionIDAndRefreshedAtParams) (db.Session, error)
	UpdateSessionLastSeenToNowFn                func(ctx context.Context, id []byte) (db.Session, error)
}

func (q *MockSessionQueries) CreateSession(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
	if q.CreateSessionFn != nil {
		return q.CreateSessionFn(ctx, arg)
	}

	return db.Session{ID: arg.ID, UserID: arg.UserID}, nil
}

func (q *MockSessionQueries) DeactivateSession(ctx context.Context, id []byte) error {
	if q.DeactivateSessionFn != nil {
		return q.DeactivateSessionFn(ctx, id)
	}

	return nil
}

func (q *MockSessionQueries) DeactivateLeastRecentlyUsedSessionForUser(ctx context.Context, userID int64) error {
	if q.DeactivateLeastRecentlyUsedSessionForUserFn != nil {
		return q.DeactivateLeastRecentlyUsedSessionForUserFn(ctx, userID)
	}

	return nil
}

func (q *MockSessionQueries) GetActiveSession(ctx context.Context, id []byte) (db.Session, error) {
	if q.GetActiveSessionFn != nil {
		return q.GetActiveSessionFn(ctx, id)
	}

	return db.Session{}, pgx.ErrNoRows
}

func (q *MockSessionQueries) GetSessionCountByUser(ctx context.Context, userID int64) (int64, error) {
	if q.GetSessionCountByUserFn != nil {
		return q.GetSessionCountByUserFn(ctx, userID)
	}

	return 0, nil
}

func (q *MockSessionQueries) UpdateSessionIDAndRefreshedAt(ctx context.Context, arg db.UpdateSessionIDAndRefreshedAtParams) (db.Session, error) {
	if q.UpdateSessionIDAndRefreshedAtFn != nil {
		return q.UpdateSessionIDAndRefreshedAtFn(ctx, arg)
	}

	return db.Session{ID: arg.ID_2}, nil
}

func (q *MockSessionQueries) UpdateSessionLastSeenToNow(ctx context.Context, id []byte) (db.Session, error) {
	if q.UpdateSessionLastSeenToNowFn != nil {
		return q.UpdateSessionLastSeenToNowFn(ctx, id)
	}

	return db.Session{ID: id}, nil
}
