package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

type AuthorizationMode int8

const (
	Authorization AuthorizationMode = 1 << iota
	Signature
)

var validAuthorization = regexp.MustCompile("^HMAC ")

type Authentication struct {
	Username      string `json:"username"`
	Password      string `json:"password,omitempty"`
	Timestamp     int64  `json:"timestamp"`
	Signature     string `json:"signature,omitempty"`
	Authorization string `json:"-"`
}

func (a *Authentication) CreateSignature(secret string) {
	a.Signature = computeHmac256(a.Username+"\n"+strconv.FormatInt(a.Timestamp, 10), secret)
}

func (a *Authentication) Sign(message string) (string, error) {
	if len(a.Signature) == 0 {
		return "", errors.New("No signature is available")
	}

	return computeHmac256(message, a.Signature), nil
}

func (a *Authentication) LoadRequest(r *http.Request, mode AuthorizationMode) error {
	switch mode {
	case Authorization:
		if basicauth_username, basicauth_password, basicauth_ok := r.BasicAuth(); basicauth_ok {
			a.Username = basicauth_username
			a.Password = basicauth_password
		} else if r.ContentLength > 0 {
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				return err
			}
			r.Body = ioutil.NopCloser(bytes.NewReader(body))

			err = json.Unmarshal(body, a)
			if err != nil {
				fmt.Printf("auth post err: %v\n", err)
				fmt.Printf("auth post body: %v\n", body)
				return err
			}
		}
	case Signature:
		// header values
		if timestamp := r.Header.Get("Timestamp"); len(timestamp) != 0 {
			timestamp, err := strconv.ParseInt(timestamp, 10, 64)
			if err != nil {
				return errors.New("Invalid Timestamp header")
			}
			a.Timestamp = timestamp
		}
		if username := r.Header.Get("Username"); len(username) != 0 {
			a.Username = username
		}
		if authHeader := r.Header.Get("Authorization"); len(authHeader) != 0 && validAuthorization.Match([]byte(authHeader)) {
			a.Authorization = string(authHeader[5:])
		}
	}

	return nil
}

func (a *Authentication) Authenticate(fn func(string, string) bool, secret string, sessiontimeout int64) []error {
	auth_errors := []error{}

	if len(a.Username) == 0 {
		auth_errors = append(auth_errors, errors.New("No username provided"))
	}
	if len(a.Password) == 0 {
		auth_errors = append(auth_errors, errors.New("No password provided"))
	}
	if len(auth_errors) > 0 {
		return auth_errors
	}

	if !fn(a.Username, a.Password) {
		auth_errors = append(auth_errors, errors.New("Invalid username or password"))
		return auth_errors
	}

	a.Timestamp = time.Now().Unix() + sessiontimeout
	a.CreateSignature(secret)

	return nil
}

func (a *Authentication) CheckAuthorization(r *http.Request, secret string, sessiontimeout int64) error {
	if len(a.Authorization) == 0 {
		return errors.New("No Authorization header provided")
	}
	if len(a.Username) == 0 {
		return errors.New("No Username header provided")
	}
	if a.Timestamp == 0 {
		return errors.New("No Timestamp header provided")
	} else if a.Timestamp+sessiontimeout < time.Now().Unix() {
		return errors.New("Signature has expired")
	}

	a.CreateSignature(secret)

	bodyhash := ""
	if r.Body != nil && r.ContentLength != 0 {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return err
		}
		r.Body = ioutil.NopCloser(bytes.NewReader(body))
		hasher := md5.New()
		hasher.Write([]byte(body))
		bodyhash = hex.EncodeToString(hasher.Sum(nil))
	}

	message := fmt.Sprintf("%s\n%s\n%s", r.Method, r.URL.Path, bodyhash)
	signedMessage, err := a.Sign(message)
	if err != nil {
		return err
	}

	if signedMessage != a.Authorization {
		fmt.Printf("invalid authorization; string to sign: %s\n", message)
		return errors.New("Authorization does not match request")
	}

	return nil
}

func (a *Authentication) WriteJSON(w http.ResponseWriter) error {
	jsonResponse, err := json.Marshal(a)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "text/json; charset=utf-8")
	w.Write(jsonResponse)

	return nil
}

func (a *Authentication) WriteHeaders(w http.ResponseWriter) error {
	w.Header().Set("Username", a.Username)
	w.Header().Set("Timestamp", strconv.FormatInt(a.Timestamp, 10))
	w.Header().Set("Signature", a.Signature)

	return nil
}

func computeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func CreateSessionSigningHandler(secret string, sessiontimeout int64, allowOrigins string, fn func(string, string) bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS, POST")
		w.Header().Set("Access-Control-Allow-Origin", allowOrigins)
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Timestamp, Username, Authorization")

		if r.Method == "OPTIONS" {
			return
		}

		a := &Authentication{}

		err := a.LoadRequest(r, Authorization)
		if err != nil {
			ReturnError(w, r, http.StatusInternalServerError, err)
			return
		}

		if auth_errors := a.Authenticate(fn, secret, sessiontimeout); auth_errors != nil {
			ReturnError(w, r, http.StatusForbidden, auth_errors...)
			return
		}

		a.Password = ""

		err = a.WriteJSON(w)
		if err != nil {
			ReturnError(w, r, http.StatusInternalServerError, err)
		}
	}
}

func CreateAuthorizedRequestHandler(secret string, sessiontimeout int64, allowOrigins string, methods string, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Methods", methods)
		w.Header().Set("Access-Control-Allow-Origin", allowOrigins)
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Timestamp, Username, Authorization")

		if r.Method == "OPTIONS" {
			return
		}

		a := &Authentication{}

		err := a.LoadRequest(r, Signature)
		if err != nil {
			ReturnError(w, r, http.StatusForbidden, err)
			return
		}

		err = a.CheckAuthorization(r, secret, sessiontimeout)
		if err != nil {
			ReturnError(w, r, http.StatusForbidden, err)
			return
		}

		err = a.WriteHeaders(w)
		if err != nil {
			ReturnError(w, r, http.StatusForbidden, err)
			return
		}

		fn(w, r)
	}
}
