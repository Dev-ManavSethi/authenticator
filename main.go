package main

import (
	"log"
	"net/http"

	"github.com/Dev-ManavSethi/authenticator/controllers"
)

func init() {

}

func main() {

	mux := http.NewServeMux()
	mux.HandleFunc("/login", controllers.Login)
	mux.HandleFunc("/signup", controllers.Signup)
	mux.HandleFunc("/verify", controllers.Verify)
	mux.HandleFunc("/generateAPIkey", controllers.GenAPIkey)

	log.Fatalln(http.ListenAndServe(":5000", mux))
}
