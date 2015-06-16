package main

import (
	"flag"
	"github.com/gorilla/mux"
	"net/http"
	"strconv"
)

var port = flag.Int64("port", 8080, "server port")
var secret = flag.String("secret", "secret", "api secret")
var sessiontimeout = flag.Int64("sessiontimeout", 30*60, "api secret")
var adminuserid = flag.String("adminuserid", "admin", "user id")
var adminpassword = flag.String("adminpassword", "admin", "user password")
var alloworigins = flag.String("alloworigins", "*", "allow these origins")

func CreateRouter(secret string, sessiontimeout int64, adminuserid string, adminpassword string, alloworigins string) *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/sessionsignature", CreateSessionSigningHandler(secret, sessiontimeout, alloworigins, func(userid string, password string) bool {
		return userid == adminuserid && password == adminpassword
	})).Methods("OPTIONS", "GET", "POST").Name("sessionsignature")
	r.HandleFunc("/page", CreateAuthorizedRequestHandler(secret, sessiontimeout, alloworigins, "GET, OPTIONS", CreatePageListHandler(alloworigins))).Methods("OPTIONS", "GET").Name("pagelist")
	r.HandleFunc("/page/{title:[a-zA-Z0-9]+}", CreateAuthorizedRequestHandler(secret, sessiontimeout, alloworigins, "GET, OPTIONS, POST, DELETE", CreatePageHandler(alloworigins))).Methods("OPTIONS", "GET", "POST", "DELETE").Name("page")

	return r
}

func main() {
	flag.Parse()

	r := CreateRouter(*secret, *sessiontimeout, *adminuserid, *adminpassword, *alloworigins)

	http.Handle("/", r)
	http.ListenAndServe(":"+strconv.FormatInt(*port, 10), nil)
}
