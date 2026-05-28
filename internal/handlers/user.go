package handlers // handlers are responsible for http endpoints and http related actions.

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"devinhadley/gobootstrapweb/internal/middleware"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
	"devinhadley/gobootstrapweb/internal/web"
)

type sessionCreator interface {
	CreateSession(ctx context.Context, userID int64) (session.Session, error)
}

type signUpper interface {
	SignUp(ctx context.Context, input user.AuthenticateBody) (user.User, error)
}

type logInner interface {
	LogIn(ctx context.Context, input user.AuthenticateBody) (user.User, error)
}

type authenticatedPasswordResetter interface {
	ResetPasswordForAuthenticatedUser(ctx context.Context, usr user.User, input user.AuthenticatedPasswordResetBody) error
}

type passwordResetRequester interface {
	CreatePasswordResetRequest(ctx context.Context, reqBody user.CreatePasswordResetRequestBody) error
}

type tokenPasswordResetter interface {
	ResetPasswordFromResetRequest(ctx context.Context, token string, input user.ResetPasswordFromResetRequestBody) error
}

func CreateSignUpHandler(userService signUpper, sessionService sessionCreator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody user.AuthenticateBody
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&reqBody)
		if err != nil {
			web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}

		usr, err := userService.SignUp(r.Context(), user.AuthenticateBody{
			Email:    reqBody.Email,
			Password: reqBody.Password,
		})
		if err != nil {
			if writeSignUpError(w, err) {
				return
			}

			web.WriteAndReportInternalError(w)
			return
		}

		newSession, err := sessionService.CreateSession(r.Context(), usr.DBUser().ID)
		if err != nil {
			web.WriteAndReportInternalError(w)
			return
		}
		web.AddSessionToCookie(w, newSession.DBSession().ID, newSession.GetAbsoluteExpiration())

		w.WriteHeader(http.StatusNoContent)
	}
}

func CreateLoginHandler(userService logInner, sessionService sessionCreator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody user.AuthenticateBody
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&reqBody)
		if err != nil {
			web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}

		usr, err := userService.LogIn(r.Context(), user.AuthenticateBody{
			Email:    reqBody.Email,
			Password: reqBody.Password,
		})
		if err != nil {
			if writeLogInError(w, err) {
				return
			}

			web.WriteAndReportInternalError(w)
			return
		}

		newSession, err := sessionService.CreateSession(r.Context(), usr.DBUser().ID)
		if err != nil {
			web.WriteAndReportInternalError(w)
			return
		}
		web.AddSessionToCookie(w, newSession.DBSession().ID, newSession.GetAbsoluteExpiration())

		w.WriteHeader(http.StatusNoContent)
	}
}

func CreateAuthenticatedPasswordResetHandler(userService authenticatedPasswordResetter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody user.AuthenticatedPasswordResetBody

		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&reqBody)
		if err != nil {
			web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}

		// TODO: Make me middleware!
		// Handler should exit early if no get user closure in context!
		// That is views that expect authentication should never ever handle user not in context.
		usr, err := middleware.UserFromContext(r.Context())
		if err != nil {
			if errors.Is(err, middleware.ErrUserNotInContext) {
				web.WriteJSONResponse(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
				return
			}
			log.Printf("when getting user for authenticated password reset: %v", err)
			web.WriteAndReportInternalError(w)
			return
		}

		err = userService.ResetPasswordForAuthenticatedUser(r.Context(), usr, reqBody)
		if err != nil {
			if writeAuthenticatedPasswordResetError(w, err) {
				return
			}
			web.WriteAndReportInternalError(w)
			return
		}

		web.ClearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
	}
}

func CreatePasswordResetRequestHandler(userService passwordResetRequester) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody user.CreatePasswordResetRequestBody

		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&reqBody)
		if err != nil {
			web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}

		err = userService.CreatePasswordResetRequest(r.Context(), reqBody)
		if err != nil {
			if writeCreatePasswordResetRequestError(w, err) {
				return
			}

			web.WriteAndReportInternalError(w)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func CreateTokenPasswordResetHandler(userService tokenPasswordResetter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")

		var reqBody user.ResetPasswordFromResetRequestBody
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&reqBody)
		if err != nil {
			web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}

		err = userService.ResetPasswordFromResetRequest(r.Context(), token, reqBody)
		if err != nil {
			if writeTokenPasswordResetError(w, err) {
				return
			}

			web.WriteAndReportInternalError(w)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func writeSignUpError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrEmailBlank) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email may not be blank"})
		return true
	}

	if errors.Is(err, user.ErrEmailTaken) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email already in use"})
		return true
	}

	if errors.Is(err, user.ErrInvalidEmail) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email is not valid"})
		return true
	}

	if writeWeakPasswordError(w, err) {
		return true
	}

	return false
}

func writeLogInError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrInvalidCredentials) {
		web.WriteJSONResponse(w, http.StatusUnauthorized, map[string]any{"error": "authentication failed"})
		return true
	}

	if errors.Is(err, user.ErrInvalidLogInInput) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "email and password may not be blank"})
		return true
	}

	if errors.Is(err, user.ErrInvalidEmail) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email is not valid"})
		return true
	}

	if errors.Is(err, user.ErrRateLimit) {
		web.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]any{"error": "try again later"})
		return true
	}

	return false
}

func writeAuthenticatedPasswordResetError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrInvalidCredentials) {
		web.WriteJSONResponse(w, http.StatusUnauthorized, map[string]any{"error": "authentication failed"})
		return true
	}

	if writeWeakPasswordError(w, err) {
		return true
	}

	return false
}

func writeCreatePasswordResetRequestError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrInvalidEmail) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email is not valid"})
		return true
	}

	if errors.Is(err, user.ErrRateLimit) {
		web.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]any{"error": "try again later"})
		return true
	}

	if errors.Is(err, user.ErrUserNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return true
	}

	return false
}

func writeTokenPasswordResetError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrInvalidResetToken) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid or expired reset token"})
		return true
	}

	if writeWeakPasswordError(w, err) {
		return true
	}

	return false
}

func writeWeakPasswordError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrPasswordEmpty) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password can't be empty"})
		return true
	}

	if errors.Is(err, user.ErrPasswordShort) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password must be 13 or more characters"})
		return true
	}

	if errors.Is(err, user.ErrPasswordLong) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password must be 256 charactrs or less"})
		return true
	}

	if errors.Is(err, user.ErrPasswordCommon) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password too common"})
		return true
	}

	return false
}
