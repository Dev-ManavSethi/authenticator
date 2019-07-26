package main

import (
	"log"
	"net/http"
)

func init() {

}

func main() {

	mux := http.NewServeMux()
	mux.HandleFunc("/login", Login)
	mux.HandleFunc("/signup", Signup)
	mux.HandleFunc("/verify", Verify)
	mux.HandleFunc("/generateAPIkey", GenAPIkey)

	log.Fatalln(http.ListenAndServe(":5000", mux))
}
