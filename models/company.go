package models

import "crypto/dsa"

type (
	Company struct {
		Name       string
		ID string
		PrivateKey dsa.PrivateKey
		Pubkey     dsa.PublicKey
		Users      []User
	}

	User struct{
		Name string
		ID string
		Password []byte
	}
)
