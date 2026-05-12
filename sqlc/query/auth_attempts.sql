-- name: CountFailedAuthAttemptsSince :one
SELECT COUNT(*)
FROM auth_attempts
WHERE action = $1
AND email = $2
AND created_at >= $3
AND outcome = 'failed';

-- name: CreateLoginAuthAttempt :exec
INSERT INTO auth_attempts (
  action, email, outcome
) VALUES ( $1, $2, $3 );
