package main

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestBasicAuth(t *testing.T) {
	router := CreateRouter("test", 30*60, "test", "test", "*")

	// BasicAuth
	r, err := MakeSignatureRequest(router, "BasicAuth", "test", "test")
	if err != nil {
		t.Fatalf("requesting signature returned error %v", err)
	}

	CheckAuthResponse("test", "test", r, t)
}

func TestPostAuth(t *testing.T) {
	router := CreateRouter("test", 30*60, "test", "test", "*")

	// BasicAuth
	r, err := MakeSignatureRequest(router, "Post", "test", "test")
	if err != nil {
		t.Fatalf("requesting signature returned error %v", err)
	}

	CheckAuthResponse("test", "test", r, t)
}

func CheckAuthResponse(expectedusername string, secret string, w *httptest.ResponseRecorder, t *testing.T) {
	if w.Code != 200 {
		if w.Code == 301 || w.Code == 302 {
			t.Logf("redirecting to: %s", w.HeaderMap.Get("Location"))
		}
		t.Errorf("got response code = %d, expected %d", w.Code, 200)
	}

	if w.Body.Len() == 0 {
		t.Errorf("expected non-zero length body")
	}

	var dat map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &dat); err != nil {
		t.Fatalf("parsing response returned error %v", err)
	}

	// required keys
	for _, k := range []string{"timestamp", "username", "signature"} {
		if _, ok := dat[k]; !ok {
			t.Log(w.Body.String())
			t.Errorf("no %s in response", k)
		}
	}

	// expected values
	for k, v := range dat {
		switch k {
		case "timestamp":
			if timestamp := int64(v.(float64)); timestamp == 0 {
				t.Errorf("expected non-zero timestamp")
			}
		case "username":
			if username := v.(string); username != expectedusername {
				t.Errorf("got username %s, expected %s", username, expectedusername)
			}
		case "signature":
			if signature := v.(string); signature != computeHmac256(expectedusername+"\n"+strconv.FormatInt(int64(dat["timestamp"].(float64)), 10), secret) {
				t.Errorf("got signature %s, expected %s", signature, computeHmac256(expectedusername+"\n"+strconv.FormatInt(int64(dat["timestamp"].(float64)), 10), secret))
			}
		default:
			t.Errorf("unknown response key %s", k)
		}
	}
}
