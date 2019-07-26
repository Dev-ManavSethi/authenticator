package controllers

import (
	"crypto/dsa"
	"crypto/rand"
	"fmt"
	"net/http"
	"os"

	"github.com/Dev-ManavSethi/authenticator/models"
)

func GenAPIkey(w http.ResponseWriter, r *http.Request) {

	params := new(dsa.Parameters)

	// see http://golang.org/pkg/crypto/dsa/#ParameterSizes
	if err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	privatekey := new(dsa.PrivateKey)
	privatekey.PublicKey.Parameters = *params

	dsa.GenerateKey(privatekey, rand.Reader) // this generates a public & private key pair

	var pubkey dsa.PublicKey
	pubkey = privatekey.PublicKey

	fmt.Println("Private Key generated")
	//fmt.Printf("%x \n", privatekey)

	fmt.Println("Public Key generated")
	//fmt.Printf("%x \n", pubkey)

	models.Keys[privatekey] = models.User{}
}

func Login(w http.ResponseWriter, r *http.Request) {

}

func Signup(w http.ResponseWriter, r *http.Request) {

}

func Verify(w http.ResponseWriter, r *http.Request) {

}
