package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
)

func SignRequest(r *http.Request, method string, url string, body []byte, a *Authentication) {
	// calculate authorization message
	bodyhash := ""
	if body != nil && len(body) != 0 {
		hasher := md5.New()
		hasher.Write([]byte(body))
		bodyhash = hex.EncodeToString(hasher.Sum(nil))
	}
	message := fmt.Sprintf("%s\n%s\n%s", method, url, bodyhash)

	// sign message
	key := []byte(a.Signature)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	signedmessage := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// set headers on request
	r.Header.Set("Username", a.Username)
	r.Header.Set("Timestamp", strconv.FormatInt(a.Timestamp, 10))
	r.Header.Set("Authorization", fmt.Sprintf("HMAC %s", signedmessage))
}

func MakeSignatureRequest(router *mux.Router, mode string, username string, password string) (*httptest.ResponseRecorder, error) {
	var r *http.Request
	var err error
	w := httptest.NewRecorder()

	switch mode {
	case "BasicAuth":
		r, err = http.NewRequest("GET", "/sessionsignature", nil)
		if err != nil {
			return nil, err
		}
		r.SetBasicAuth(username, password)
	case "Post":
		post_data := map[string]string{"username": username, "password": password}
		json_bytes, err := json.Marshal(post_data)
		if err != nil {
			return nil, err
		}
		r, err = http.NewRequest("POST", "/sessionsignature", bytes.NewBuffer(json_bytes))
		if err != nil {
			return nil, err
		}
	}
	router.ServeHTTP(w, r)

	return w, nil
}

func GetAuthorization(router *mux.Router) (*Authentication, error) {
	r, err := MakeSignatureRequest(router, "BasicAuth", "test", "test")
	if err != nil {
		return nil, err
	}

	var dat map[string]interface{}
	if err := json.Unmarshal(r.Body.Bytes(), &dat); err != nil {
		return nil, err
	}
	username := dat["username"].(string)
	timestamp := int64(dat["timestamp"].(float64))
	signature := dat["signature"].(string)

	return &Authentication{Username: username, Timestamp: timestamp, Signature: signature}, nil
}

func MakeRequest(router *mux.Router, method string, url string, body []byte, a *Authentication) (*httptest.ResponseRecorder, map[string]interface{}, error) {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
	if a != nil {
		SignRequest(r, method, url, body, a)
	}
	router.ServeHTTP(w, r)

	var dat map[string]interface{}
	if w.Body.Len() != 0 {
		err := json.Unmarshal(w.Body.Bytes(), &dat)
		return w, dat, err
	}

	return w, dat, nil
}

func RemoveIfExists(filename string) error {
	switch _, err := os.Stat(filename); {
	case err != nil && os.IsNotExist(err):
		return nil
	case err != nil:
		return err
	}

	return os.Remove(filename)
}
