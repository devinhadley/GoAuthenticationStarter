package session

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/service/user"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type SessionQueries interface {
	CreateSession(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	DeactivateLeastRecentlyUsedSessionForUser(ctx context.Context, userID int64) error
	GetActiveSession(ctx context.Context, id []byte) (db.Session, error)
	GetSessionCountByUser(ctx context.Context, userID int64) (int64, error)
	UpdateSessionIDAndRefreshedAt(ctx context.Context, arg db.UpdateSessionIDAndRefreshedAtParams) (db.Session, error)
	UpdateSessionLastSeenToNow(ctx context.Context, id []byte) (db.Session, error)
	DeactivateSession(ctx context.Context, id []byte) error
}

type Service struct {
	queries SessionQueries
}

func NewService(queries SessionQueries) *Service {
	return &Service{
		queries: queries,
	}
}

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrSessionNotFound = errors.New("session not found")
)

const MaxNumberOfActiveSessions = 10

func (s *Service) CreateSession(ctx context.Context, usr user.User) (Session, error) {
	numSessions, err := s.queries.GetSessionCountByUser(ctx, usr.DBUser().ID)
	if err != nil {
		return Session{}, fmt.Errorf("getting session count: %w", err)
	}

	if numSessions >= MaxNumberOfActiveSessions {
		err = s.queries.DeactivateLeastRecentlyUsedSessionForUser(ctx, usr.DBUser().ID)
		if err != nil {
			return Session{}, fmt.Errorf("deactivating least recently used session: %w", err)
		}
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return Session{}, fmt.Errorf("generating session id: %w", err)
	}

	session, err := s.queries.CreateSession(ctx, db.CreateSessionParams{
		ID:     sessionID,
		UserID: usr.DBUser().ID,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" && pgErr.ConstraintName == "sessions_user_id_fkey" {
			return Session{}, ErrUserNotFound
		}

		return Session{}, fmt.Errorf("creating session: %w", err)
	}

	return SessionFromDB(session), nil
}

func (s *Service) GetSession(ctx context.Context, sessionID []byte) (Session, error) {
	session, err := s.queries.GetActiveSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrSessionNotFound
		}
		return Session{}, fmt.Errorf("getting session: %w", err)
	}

	return SessionFromDB(session), nil
}

func (s *Service) ExpireSession(ctx context.Context, sessionID []byte) error {
	err := s.queries.DeactivateSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("expiring session: %w", err)
	}

	return nil
}

func (s *Service) UpdateLastSeen(ctx context.Context, session Session) error {
	// Prevents us from updating the session on every request...
	if session.ShouldUpdateLastSeen() {
		_, err := s.queries.UpdateSessionLastSeenToNow(ctx, session.DBSession().ID)
		if err != nil {
			return fmt.Errorf("updating session last seen: %w", err)
		}
	}
	return nil
}

func (s *Service) RotateSession(ctx context.Context, sessionID []byte) (Session, error) {
	rotatedSessionID, err := generateSessionID()
	if err != nil {
		return Session{}, err
	}

	updatedSession, err := s.queries.UpdateSessionIDAndRefreshedAt(ctx, db.UpdateSessionIDAndRefreshedAtParams{
		ID:   sessionID,
		ID_2: rotatedSessionID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrSessionNotFound
		}

		return Session{}, fmt.Errorf("rotating session: %w", err)
	}

	return SessionFromDB(updatedSession), nil
}

func generateSessionID() ([]byte, error) {
	sessionID := make([]byte, 16)
	_, err := rand.Read(sessionID)
	if err != nil {
		return nil, err
	}

	return sessionID, nil
}
