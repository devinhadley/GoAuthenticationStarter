// Package web provides shared http utilities.
package web

import (
	"encoding/json"
	"net/http"
)

func WriteJSONResponse(w http.ResponseWriter, statusCode int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func WriteAndReportInternalError(w http.ResponseWriter) {
	// TODO: Log internal errors to Sentry or another monitoring service.
	WriteJSONResponse(w, http.StatusInternalServerError, map[string]any{"error": "an internal error occured"})
}

// DecodeJSONBodyOrWriteError decodes the request body into T, rejecting unknown fields.
// On failure it writes a 400 "invalid JSON body" response and returns ok=false;
// callers should simply return when ok is false.
func DecodeJSONBodyOrWriteError[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var body T
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return body, false
	}
	return body, true
}
