// Package pgerr provides helpers for inspecting Postgres error codes.
package pgerr

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// See https://www.postgresql.org/docs/current/errcodes-appendix.html
const (
	uniqueViolation     = "23505"
	foreignKeyViolation = "23503"
)

func IsUniqueViolation(err error) bool {
	return hasCode(err, uniqueViolation)
}

func IsForeignKeyViolation(err error) bool {
	return hasCode(err, foreignKeyViolation)
}

func hasCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
