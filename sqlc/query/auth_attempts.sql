-- name: CreateLoginAuthAttempt :exec
INSERT INTO auth_attempts (
  action, email, outcome
) VALUES ( $1, $2, $3 );

-- name: CountFailedAuthAttemptsSince :one
SELECT COUNT(*)
FROM auth_attempts
WHERE action = $1
AND email = $2
AND outcome = 'failed'
AND created_at >= $3;

-- name: CountAuthAttemptsForPassResetReq :one
SELECT 
  COUNT(*) AS old_count,
  COUNT(*) FILTER (WHERE created_at >= (sqlc.arg(recent_date))) AS recent_count
FROM auth_attempts
WHERE action = 'password_reset'
  AND email = sqlc.arg(email)
  AND outcome = 'succeeded'
  AND created_at >= sqlc.arg(old_date); -- long entries range will include short entries...
