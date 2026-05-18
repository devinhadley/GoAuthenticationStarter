package handlers // handlers are responsible for http endpoints and http related actions.

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"devinhadley/gobootstrapweb/internal/middleware"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
	"devinhadley/gobootstrapweb/internal/utils"
)

func CreateSignUpHandler(userService *user.Service, sessionService *session.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody user.AuthenticateBody
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&reqBody)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
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

			utils.WriteAndReportInternalError(w)
			return
		}

		newSession, err := sessionService.CreateSession(r.Context(), usr)
		if err != nil {
			utils.WriteAndReportInternalError(w)
			return
		}
		utils.AddSessionToCookie(w, newSession.DBSession().ID, newSession.GetAbsoluteExpiration())

		// TODO: should be 204 no content...
		w.WriteHeader(http.StatusOK)
	}
}

func CreateLoginHandler(userService *user.Service, sessionService *session.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody user.AuthenticateBody
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&reqBody)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
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

			utils.WriteAndReportInternalError(w)
			return
		}

		newSession, err := sessionService.CreateSession(r.Context(), usr)
		if err != nil {
			utils.WriteAndReportInternalError(w)
			return
		}
		utils.AddSessionToCookie(w, newSession.DBSession().ID, newSession.GetAbsoluteExpiration())

		// TODO: should be 204 no content...
		w.WriteHeader(http.StatusOK)
	}
}

func CreateAuthenticatedPasswordResetHandler(userService *user.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody user.PasswordResetBody

		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&reqBody)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}

		// TODO: Make me middleware!
		// Handler should exit early if no get user closure in context!
		// That is views that expect authentication should never ever handle user not in context.
		usr, err := middleware.UserFromContext(r.Context())
		if err != nil {
			if errors.Is(err, middleware.ErrUserNotInContext) {
				utils.WriteJSONResponse(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
				return
			}
			log.Printf("when getting user for authenticated password reset: %v", err)
			utils.WriteAndReportInternalError(w)
			return
		}

		err = userService.ResetPasswordForAuthenticatedUser(r.Context(), usr, reqBody)
		if err != nil {
			if writeAuthenticatedPasswordResetError(w, err) {
				return
			}
			utils.WriteAndReportInternalError(w)
			return
		}

		utils.ClearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
	}
}

func writeSignUpError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrEmailBlank) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email may not be blank"})
		return true
	}

	if errors.Is(err, user.ErrEmailTaken) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email already in use"})
		return true
	}

	if errors.Is(err, user.ErrInvalidEmail) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email is not valid"})
		return true
	}

	if writeWeakPasswordError(w, err) {
		return true
	}

	return false
}

func writeLogInError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrInvalidCredentials) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "authentication failed"})
		return true
	}

	if errors.Is(err, user.ErrInvalidLogInInput) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "email and password may not be blank"})
		return true
	}

	if errors.Is(err, user.ErrInvalidEmail) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email is not valid"})
		return true
	}

	if errors.Is(err, user.ErrLoginRateLimit) {
		utils.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]any{"error": "try again later"})
		return true
	}

	return false
}

func writeAuthenticatedPasswordResetError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrInvalidCredentials) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "authentication failed"})
		return true
	}

	if writeWeakPasswordError(w, err) {
		return true
	}

	return false
}

func writeWeakPasswordError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrPasswordEmpty) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password can't be empty"})
		return true
	}

	if errors.Is(err, user.ErrPasswordShort) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password must be 13 or more characters"})
		return true
	}

	if errors.Is(err, user.ErrPasswordLong) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password must be 256 charactrs or less"})
		return true
	}

	if errors.Is(err, user.ErrPasswordCommon) {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password too common"})
		return true
	}

	return false
}
