package mergeitis

import (
	"fmt"
	"net/http"
)

func init() {
	http.HandleFunc("/", Handler)
	http.HandleFunc("/oauth/", HandlerOAuth)
	http.HandleFunc("/signin/", HandlerSignIn)
	http.HandleFunc("/user/", HandlerUser)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello")
}
