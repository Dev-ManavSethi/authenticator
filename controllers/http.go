package controllers

import (
	"crypto/dsa"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"os"

	uuid "github.com/satori/go.uuid"
)

func GenAPIkey(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {

	} else {

		//name := r.FormValue("name")
		uuid, err := uuid.NewV4()
		if err != nil {

		} else {

			id := uuid.String()
			log.Println(id)

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

			// models.KeyPair[*privatekey] = models.Company{
			// 	Name:       name,
			// 	ID:         id,
			// 	PrivateKey: *privatekey,
			// 	Pubkey:     pubkey,
			// 	Users:      []models.User{},
			// }

			privatekeyfile, err := os.Create("DSAprivate.key")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			privatekeyencoder := gob.NewEncoder(privatekeyfile)
			privatekeyencoder.Encode(privatekey)
			privatekeyfile.Close()

			publickeyfile, err := os.Create("DSApublic.key")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			publickeyencoder := gob.NewEncoder(publickeyfile)
			publickeyencoder.Encode(pubkey)
			publickeyfile.Close()

		}
	}
}

func Login(w http.ResponseWriter, r *http.Request) {

}

func Signup(w http.ResponseWriter, r *http.Request) {

}

func Verify(w http.ResponseWriter, r *http.Request) {

}
