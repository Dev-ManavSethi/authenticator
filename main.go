package main

import (
	"log"
	"net/http"

	"github.com/Dev-ManavSethi/authenticator/controller"
)

func init() {

}

func main() {

	mux := http.NewServeMux()
	mux.HandleFunc("/login", controller.Login)
	mux.HandleFunc("/signup", controller.Signup)
	mux.HandleFunc("/verify", controller.Verify)
	mux.HandleFunc("/generateAPIkey", controller.GenAPIkey)

	log.Fatalln(http.ListenAndServe(":5000", mux))
}
