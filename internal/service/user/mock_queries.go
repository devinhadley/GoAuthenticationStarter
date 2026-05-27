package user

import (
	"context"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5"
)

type MockQueries struct {
	CreateUserFn                       func(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUserByEmailFn                   func(ctx context.Context, email string) (db.User, error)
	GetUserByIDFn                      func(ctx context.Context, id int64) (db.User, error)
	CountFailedAuthAttemptsSinceFn     func(ctx context.Context, arg db.CountFailedAuthAttemptsSinceParams) (int64, error)
	CountAuthAttemptsForPassResetReqFn func(ctx context.Context, arg db.CountAuthAttemptsForPassResetReqParams) (db.CountAuthAttemptsForPassResetReqRow, error)
	CreateLoginAuthAttemptFn           func(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error
	CreatePasswordResetRequestFn       func(ctx context.Context, arg db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error)
	ConsumePasswordResetRequestFn      func(ctx context.Context, id []byte) (db.PasswordResetRequest, error)
	UpdatePasswordHashFn               func(ctx context.Context, arg db.UpdatePasswordHashParams) error
}

func (q *MockQueries) CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
	if q.CreateUserFn != nil {
		return q.CreateUserFn(ctx, arg)
	}

	return db.User{
		ID:           1,
		Email:        arg.Email,
		PasswordHash: arg.PasswordHash,
	}, nil
}

func (q *MockQueries) GetUserByEmail(ctx context.Context, email string) (db.User, error) {
	if q.GetUserByEmailFn != nil {
		return q.GetUserByEmailFn(ctx, email)
	}

	return db.User{
		ID:    1,
		Email: email,
	}, nil
}

func (q *MockQueries) GetUserByID(ctx context.Context, id int64) (db.User, error) {
	if q.GetUserByIDFn != nil {
		return q.GetUserByIDFn(ctx, id)
	}

	return db.User{
		ID:    id,
		Email: "test@example.com",
	}, nil
}

func (q *MockQueries) CountFailedAuthAttemptsSince(ctx context.Context, arg db.CountFailedAuthAttemptsSinceParams) (int64, error) {
	if q.CountFailedAuthAttemptsSinceFn != nil {
		return q.CountFailedAuthAttemptsSinceFn(ctx, arg)
	}
	return 0, nil
}

func (q *MockQueries) CountAuthAttemptsForPassResetReq(ctx context.Context, arg db.CountAuthAttemptsForPassResetReqParams) (db.CountAuthAttemptsForPassResetReqRow, error) {
	if q.CountAuthAttemptsForPassResetReqFn != nil {
		return q.CountAuthAttemptsForPassResetReqFn(ctx, arg)
	}

	return db.CountAuthAttemptsForPassResetReqRow{}, nil
}

func (q *MockQueries) CreateLoginAuthAttempt(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error {
	if q.CreateLoginAuthAttemptFn != nil {
		return q.CreateLoginAuthAttemptFn(ctx, arg)
	}

	return nil
}

func (q *MockQueries) CreatePasswordResetRequest(ctx context.Context, arg db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error) {
	if q.CreatePasswordResetRequestFn != nil {
		return q.CreatePasswordResetRequestFn(ctx, arg)
	}

	return db.PasswordResetRequest{ID: arg.ID, UserID: arg.UserID}, nil
}

func (q *MockQueries) ConsumePasswordResetRequest(ctx context.Context, id []byte) (db.PasswordResetRequest, error) {
	if q.ConsumePasswordResetRequestFn != nil {
		return q.ConsumePasswordResetRequestFn(ctx, id)
	}

	return db.PasswordResetRequest{}, pgx.ErrNoRows
}

func (q *MockQueries) UpdatePasswordHash(ctx context.Context, arg db.UpdatePasswordHashParams) error {
	if q.UpdatePasswordHashFn != nil {
		return q.UpdatePasswordHashFn(ctx, arg)
	}

	return nil
}
