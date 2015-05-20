package main

import (
	"encoding/json"
	"net/http"
)

type ErrorResponse struct {
	Errors []string `json:"errors"`
}

func ReturnError(w http.ResponseWriter, r *http.Request, status int, e ...error) {
	er := &ErrorResponse{Errors: make([]string, len(e))}
	for i, err := range e {
		er.Errors[i] = err.Error()
	}

	w.Header().Set("Content-Type", "text/json; charset=utf-8")
	w.WriteHeader(status)
	jsonResponse, _ := json.Marshal(er)
	w.Write(jsonResponse)
}
