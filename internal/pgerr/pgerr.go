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

func IsUniqueViolation(err error, constraintName string) bool {
	return hasConstraintViolation(err, uniqueViolation, constraintName)
}

func IsForeignKeyViolation(err error, constraintName string) bool {
	return hasConstraintViolation(err, foreignKeyViolation, constraintName)
}

func hasConstraintViolation(err error, code, constraintName string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) &&
		pgErr.Code == code &&
		pgErr.ConstraintName == constraintName
}