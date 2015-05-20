package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
)

func CheckAuthHeader(expectedusername string, secret string, w *httptest.ResponseRecorder, t *testing.T) {
	var dat map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &dat); w.Body.Len() > 0 && err != nil {
		t.Fatalf("parsing response returned error %v", err)
	}

	timestamp, err := strconv.ParseInt(w.Header().Get("timestamp"), 10, 64)
	if err != nil {
		t.Logf("headers: %v", w.Header())
		t.Logf("body: %s", w.Body.String())
		t.Fatalf("parsing timestamp header returned error %v", err)
	} else if timestamp == 0 {
		t.Logf("headers: %v", w.Header())
		t.Logf("body: %s", w.Body.String())
		t.Errorf("expected non-zero timestamp")
	}
	if username := w.Header().Get("Username"); username != expectedusername {
		t.Logf("headers: %v", w.Header())
		t.Logf("body: %s", w.Body.String())
		t.Errorf("got username %s, expected %s", username, expectedusername)
	}
	if signature := w.Header().Get("Signature"); signature != computeHmac256(expectedusername+"\n"+strconv.FormatInt(timestamp, 10), secret) {
		t.Logf("headers: %v", w.Header())
		t.Logf("body: %s", w.Body.String())
		t.Errorf("got signature %s, expected %s", signature, computeHmac256(expectedusername+"\n"+strconv.FormatInt(timestamp, 10), secret))
	}
}

func TestPageListGet(t *testing.T) {
	router := CreateRouter("test", 30*60, "test", "test", "*")

	// remove extraneous files
	if files, err := ioutil.ReadDir("data/"); err != nil {
		t.Fatalf("getting file list returned error %v", err)
	} else {
		for _, file := range files {
			if file.Name() != "TestPage.txt" {
				if err := RemoveIfExists("data/" + file.Name()); err != nil {
					t.Fatalf("deleting file returned error %v", err)
				}
			}
		}
	}

	// create test file
	err := ioutil.WriteFile("data/TestPage.txt", []byte("Test result"), 0600)
	if err != nil {
		t.Fatalf("creating test file returned error %v", err)
	}

	// get authorization
	a, err := GetAuthorization(router)
	if err != nil {
		t.Fatalf("retrieving authorization returned error %v", err)
	}

	// make request
	r, dat, err := MakeRequest(router, "GET", "/page", nil, a)
	if err != nil {
		t.Fatalf("running request returned error %v", err)
	}

	// authorization headers
	CheckAuthHeader("test", "test", r, t)

	// required keys
	for _, k := range []string{"items"} {
		if _, ok := dat[k]; !ok {
			t.Errorf("no %s in response", k)
		}
	}
	// expected values
	for k, v := range dat {
		switch k {
		case "items":
			if items := v.([]interface{}); len(items) != 1 {
				t.Errorf("got %d results, expected %d", len(items), 1)
			} else {
				item := items[0].(map[string]interface{})
				if title := item["title"].(string); title != "TestPage" {
					t.Errorf("got title %s, expected %s", title, "TestPage")
				}
			}
		default:
			t.Errorf("unknown response key %s", k)
		}
	}
}

func TestPageGet(t *testing.T) {
	router := CreateRouter("test", 30*60, "test", "test", "*")

	// create test file
	err := ioutil.WriteFile("data/TestPage.txt", []byte("Test result"), 0600)
	if err != nil {
		t.Fatalf("creating test file returned error %v", err)
	}

	// get authorization
	a, err := GetAuthorization(router)
	if err != nil {
		t.Fatalf("retrieving authorization returned error %v", err)
	}

	// make request
	r, dat, err := MakeRequest(router, "GET", "/page/TestPage", nil, a)
	if err != nil {
		t.Fatalf("running request returned error %v", err)
	}

	// authorization headers
	CheckAuthHeader("test", "test", r, t)

	// required keys
	for _, k := range []string{"title", "body"} {
		if _, ok := dat[k]; !ok {
			t.Errorf("no %s in response", k)
		}
	}
	// expected values
	for k, v := range dat {
		switch k {
		case "title":
			if title := v.(string); title != "TestPage" {
				t.Errorf("got title %s, expected %s", title, "TestPage")
			}
		case "body":
			if body := v.(string); body != "Test result" {
				t.Errorf("got body %s, expected %s", body, "Test result")
			}
		default:
			t.Errorf("unknown response key %s", k)
		}
	}
}

func TestPagePostNew(t *testing.T) {
	router := CreateRouter("test", 30*60, "test", "test", "*")

	err := RemoveIfExists("data/TestPageNew.txt")
	if err != nil {
		t.Fatalf("removing existing test page returned error %v", err)
	}

	// get authorization
	a, err := GetAuthorization(router)
	if err != nil {
		t.Fatalf("retrieving authorization returned error %v", err)
	}

	// create post data
	postMap := map[string]string{"title": "TestPageNew", "body": "Test result"}
	postBytes, err := json.Marshal(postMap)
	if err != nil {
		t.Fatalf("serializing post data returned error %v", err)
	}

	r, dat, err := MakeRequest(router, "POST", "/page/TestPageNew", postBytes, a)
	if err != nil {
		t.Fatalf("running request returned error %v", err)
	}

	// authorization headers
	CheckAuthHeader("test", "test", r, t)

	// required keys
	for _, k := range []string{"title", "body"} {
		if _, ok := dat[k]; !ok {
			t.Errorf("no %s in response", k)
		}
	}
	// expected values
	for k, v := range dat {
		switch k {
		case "title":
			if title := v.(string); title != "TestPageNew" {
				t.Errorf("got title %s, expected %s", title, "TestPage")
			}
		case "body":
			if body := v.(string); body != "Test result" {
				t.Errorf("got body %s, expected %s", body, "Test result")
			}
		default:
			t.Errorf("unknown response key '%s': %v", k, v)
		}
	}

	err = RemoveIfExists("data/TestPageNew.txt")
	if err != nil {
		t.Fatalf("removing new page returned error %v", err)
	}
}

func TestPageDelete(t *testing.T) {
	router := CreateRouter("test", 30*60, "test", "test", "*")
	filename := "data/TestPageNew.txt"

	// create test file
	err := ioutil.WriteFile(filename, []byte("Test result"), 0600)
	if err != nil {
		t.Fatalf("creating test file returned error %v", err)
	}

	// get authorization
	a, err := GetAuthorization(router)
	if err != nil {
		t.Fatalf("retrieving authorization returned error %v", err)
	}

	r, _, err := MakeRequest(router, "DELETE", "/page/TestPageNew", []byte{}, a)
	if err != nil {
		t.Fatalf("running request returned error %v", err)
	}

	// authorization headers
	CheckAuthHeader("test", "test", r, t)

	// check that file no longer exists
	switch _, err := os.Stat(filename); {
	case err != nil && os.IsNotExist(err):
		// do nothing
	case err != nil:
		t.Fatalf("new page should no longer exist %v", err)
	}

	err = RemoveIfExists(filename)
	if err != nil {
		t.Fatalf("removing new page returned error %v", err)
	}
}
