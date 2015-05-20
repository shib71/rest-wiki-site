package main

import (
	"bytes"
	"encoding/json"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var validPath = regexp.MustCompile("^/(edit|save|view)/([a-zA-Z0-9]+)$")

type Page struct {
	Title string `json:"title"`
	Body  string `json:"body,omitempty"`
}

func (p *Page) Filename() string {
	return "data/" + p.Title + ".txt"
}

func (p *Page) Exists() bool {
	filename := p.Filename()

	// make sure directory exists
	switch _, err := os.Stat("data/"); {
	case err != nil && os.IsNotExist(err):
		os.Mkdir("data", 0600)
	case err != nil:
		panic(err)
	}

	if _, err := os.Stat(filename); err != nil {
		return false
	} else {
		return true
	}
}

func (p *Page) Load() error {
	if !p.Exists() {
		return nil
	}

	filename := p.Filename()

	// read file
	body, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	p.Body = string(body)

	return nil
}

func (p *Page) Save() error {
	filename := p.Filename()

	// make sure directory exists
	switch _, err := os.Stat("data/"); {
	case err != nil && os.IsNotExist(err):
		os.Mkdir("data", 0600)
	case err != nil:
		panic(err)
	}

	return ioutil.WriteFile(filename, []byte(p.Body), 0600)
}

func (p *Page) Delete() error {
	if !p.Exists() {
		return nil
	}

	filename := p.Filename()

	return os.Remove(filename)
}

func loadPage(title string) (*Page, error) {
	p := &Page{Title: title}

	if err := p.Load(); err != nil {
		return p, err
	}

	return p, nil
}

type Pages struct {
	Items []*Page `json:"items"`
}

func getPages() (*Pages, error) {
	directory := "data/"

	// make sure directory exists
	switch _, err := os.Stat(directory); {
	case err != nil && os.IsNotExist(err):
		os.Mkdir("data", 0600)
	case err != nil:
		panic(err)
	}

	if files, err := ioutil.ReadDir(directory); err != nil {
		return nil, err
	} else {
		results := &Pages{}
		for _, file := range files {
			thispage := &Page{Title: strings.Split(file.Name(), ".")[0]}
			results.Items = append(results.Items, thispage)
		}

		return results, nil
	}
}

func CreatePageListHandler(allowOrigins string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Origin", allowOrigins)
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Timestamp, Username, Authorization")

		switch r.Method {
		case "OPTIONS":
			return
		case "GET":
			if pages, err := getPages(); err != nil {
				ReturnError(w, r, http.StatusInternalServerError, err)
				return
			} else {
				jsonResponse, _ := json.Marshal(pages)
				w.Header().Set("Content-Type", "text/json; charset=utf-8")
				w.Write(jsonResponse)
			}
		}
	}
}

func CreatePageHandler(allowOrigins string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		p, err := loadPage(vars["title"])

		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS, POST, DELETE")
		w.Header().Set("Access-Control-Allow-Origin", allowOrigins)
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Timestamp, Username, Authorization")

		switch r.Method {
		case "OPTIONS":
			return
		case "GET":
			if err != nil {
				http.NotFound(w, r)
				return
			}
		case "POST":
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				ReturnError(w, r, http.StatusInternalServerError, err)
				return
			}
			r.Body = ioutil.NopCloser(bytes.NewReader(body))

			err = json.Unmarshal(body, p)
			if err != nil {
				ReturnError(w, r, http.StatusInternalServerError, err)
				return
			}

			err = p.Save()
			if err != nil {
				ReturnError(w, r, http.StatusInternalServerError, err)
				return
			}
		case "DELETE":
			err = p.Delete()
			if err != nil {
				ReturnError(w, r, http.StatusInternalServerError, err)
				return
			}

			w.WriteHeader(http.StatusNoContent)
			return
		}

		jsonResponse, _ := json.Marshal(p)
		w.Header().Set("Content-Type", "text/json; charset=utf-8")
		w.Write(jsonResponse)
	}
}
