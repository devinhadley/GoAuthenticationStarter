package session

import "context"

type MockService struct {
	CreateSessionFn                func(ctx context.Context, userID int64) (Session, error)
	GetSessionFn                   func(ctx context.Context, sessionID []byte) (Session, error)
	ExpireSessionFn                func(ctx context.Context, sessionID []byte) error
	UpdateLastSeenFn               func(ctx context.Context, s Session) error
	RotateSessionFn                func(ctx context.Context, sessionID []byte) (Session, error)
	DeactivateAllSessionsForUserFn func(ctx context.Context, userID int64) error
}

func (s MockService) CreateSession(ctx context.Context, userID int64) (Session, error) {
	if s.CreateSessionFn != nil {
		return s.CreateSessionFn(ctx, userID)
	}

	return Session{}, nil
}

func (s MockService) GetSession(ctx context.Context, sessionID []byte) (Session, error) {
	if s.GetSessionFn != nil {
		return s.GetSessionFn(ctx, sessionID)
	}

	return Session{}, nil
}

func (s MockService) ExpireSession(ctx context.Context, sessionID []byte) error {
	if s.ExpireSessionFn != nil {
		return s.ExpireSessionFn(ctx, sessionID)
	}

	return nil
}

func (s MockService) UpdateLastSeen(ctx context.Context, curSession Session) error {
	if s.UpdateLastSeenFn != nil {
		return s.UpdateLastSeenFn(ctx, curSession)
	}

	return nil
}

func (s MockService) RotateSession(ctx context.Context, sessionID []byte) (Session, error) {
	if s.RotateSessionFn != nil {
		return s.RotateSessionFn(ctx, sessionID)
	}

	return Session{}, nil
}

func (s MockService) DeactivateAllSessionsForUser(ctx context.Context, userID int64) error {
	if s.DeactivateAllSessionsForUserFn != nil {
		return s.DeactivateAllSessionsForUserFn(ctx, userID)
	}

	return nil
}
