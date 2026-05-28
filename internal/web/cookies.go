package web

import (
	"encoding/base64"
	"net/http"
	"os"
	"time"
)

const (
	sessionIDCookieName = "id"
)

func AddSessionToCookie(w http.ResponseWriter, sessionID []byte, absoluteExpiration time.Time) {
	base64SessionID := base64.StdEncoding.EncodeToString(sessionID)

	cookie := http.Cookie{
		Name:     sessionIDCookieName,
		Value:    base64SessionID,
		Expires:  absoluteExpiration,
		HttpOnly: true,
		Path:     "/",
		Secure:   isSessionCookieSecure(),
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)
}

func ClearSessionCookie(w http.ResponseWriter) {
	cookie := http.Cookie{
		Name:     sessionIDCookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Path:     "/",
		Secure:   isSessionCookieSecure(),
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)
}

func isSessionCookieSecure() bool {
	isSecure := os.Getenv("USE_HTTPS")
	if isSecure == "" {
		return true
	}

	return isSecure == "true"
}
