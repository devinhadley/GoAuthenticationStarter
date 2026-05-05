package handlers // handlers are responsible for http endpoints and http related actions.

import (
	"encoding/json"
	"errors"
	"net/http"

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

		w.WriteHeader(http.StatusOK)
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

	return false
}
