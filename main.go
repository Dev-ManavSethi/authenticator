package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	Companies   map[string]Company
	GlobalMutex sync.Mutex
	DummyError  error
)

type (
	Company struct {
		Name   string
		ID     string
		APIkey string
		Users  []User
	}

	User struct {
		Name     string
		ID       string
		Password []byte
		Email    string
	}

	NexmoReqResponse struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}
	NexmoCodeVerResponse struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
		EventID   string `json:"event_id"`
		Price     string `json:"price"`
		Currency  string `json:"currency"`
	}
)

func init() {

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	Companies = make(map[string]Company)

	DummyError = nil
	Companies, DummyError = LoadDB()

	if DummyError != nil {
		log.Println("Error loading DB")
		log.Fatalln(DummyError)
	} else {
		log.Println("LOADED db")
	}

}

func main() {

	mux := http.NewServeMux()
	mux.HandleFunc("/generateAPIkey", GenAPIkey)
	mux.HandleFunc("/signup", Signup)
	mux.HandleFunc("/login", Login)
	mux.HandleFunc("/verify", Verify)
	mux.HandleFunc("/verify2", Verify2)

	log.Println("Listening on 5000")
	log.Fatalln(http.ListenAndServe(":5000", mux))
}

func GenAPIkey(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		log.Println("Error parsing form", err)
		w.WriteHeader(http.StatusInternalServerError)
	} else {

		name := r.FormValue("name")
		//check if comapny already exists

		for _, company := range Companies {
			if company.Name == name {

				fmt.Fprintln(w, "Name already exists")

				w.WriteHeader(http.StatusAlreadyReported)
				return
			}
		}

		uuid, err := uuid.NewV4()
		if err != nil {
			log.Println("Error creating uuid", err)
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			id := uuid.String()
			h := sha256.New()
			h.Write([]byte(name + "." + id))

			bytesHash := h.Sum(nil)
			hashString := hex.EncodeToString(bytesHash)

			GlobalMutex.Lock()
			Companies[hashString] = Company{
				Name:   name,
				ID:     id,
				APIkey: hashString,
				Users:  []User{},
			}

			GlobalMutex.Unlock()

			err := SaveToDB(Companies)
			if err != nil {
				log.Println("Err saving to db", err)
				w.WriteHeader(http.StatusInternalServerError)
			}

			log.Println("API key generated for company: " + name + " , id : " + id)
			fmt.Fprintln(w, "API key: "+hashString)
			fmt.Fprintln(w, "Name: "+name)
			fmt.Fprintln(w, "ID: "+id)

			w.WriteHeader(http.StatusOK)

			//save to db file

		}
	}

}

func Login(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		log.Println("Err parsing form", err)
		w.WriteHeader(http.StatusInternalServerError)
	} else {

		email := r.FormValue("email")
		pass := r.FormValue("password")
		apikey := r.FormValue("apikey")

		_, ok := Companies[apikey]

		if ok {

			Company := Companies[apikey]

			var EmailFound bool = false
			for _, user := range Company.Users {

				if user.Email == email {

					EmailFound = true
					//check password

					err := bcrypt.CompareHashAndPassword(user.Password, []byte(pass))

					if err == bcrypt.ErrMismatchedHashAndPassword {

						w.WriteHeader(http.StatusUnauthorized)
						break
					}
					if err == nil {
						w.WriteHeader(http.StatusOK)
						break
					}
					if err != nil {

						w.WriteHeader(http.StatusUnauthorized)
						break
					}
				}
			}

			if !EmailFound {

				w.WriteHeader(http.StatusUnauthorized)
			}
		}
		if !ok {

			fmt.Fprintln(w, "Incorrect api key")

			w.WriteHeader(http.StatusUnauthorized)
		}
	}

}

func Signup(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		log.Println("Error parsing form ", err)
		w.WriteHeader(http.StatusInternalServerError)
	} else {

		email := r.FormValue("email")
		pass := r.FormValue("password")
		name := r.FormValue("name")
		uuid, err := uuid.NewV4()
		if err != nil {
			log.Println("Error craeting user uuid", err)

			w.WriteHeader(http.StatusInternalServerError)
		} else {
			id := uuid.String()
			apikey := r.FormValue("apikey")

			_, ok := Companies[apikey]
			if !ok {

				w.WriteHeader(http.StatusUnauthorized)
			}
			if ok {

				Company := Companies[apikey]

				HashedPass, err := bcrypt.GenerateFromPassword([]byte(pass), 10)
				if err != nil {
					log.Println("Error craeting hashed password", err)

					w.WriteHeader(http.StatusInternalServerError)
				} else {

					Company.Users = append(Company.Users, User{
						Name:     name,
						Email:    email,
						ID:       id,
						Password: HashedPass,
					})

					GlobalMutex.Lock()
					Companies[apikey] = Company
					GlobalMutex.Unlock()

					log.Println("User signed up for company: " + Companies[apikey].Name)
					//save map to db

					err := SaveToDB(Companies)
					if err != nil {
						log.Println(err)
					}

					w.WriteHeader(http.StatusAccepted)

				}
			}
		}
	}

}

func Verify(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		log.Println("Errir parsing form", err)

		w.WriteHeader(http.StatusInternalServerError)
	} else {

		apikey := r.FormValue("apikey")

		_, ok := Companies[apikey]

		if ok {

			brandname := Companies[apikey].Name
			//log.Println(brandname)
			phoneString := r.FormValue("phone")

			//	phone, err := strconv.Atoi(phoneString)

			//send code to phone
			url := "https://api.nexmo.com/verify/json?api_key=6d52c704&api_secret=KfFCibpdpshkPpr2&number=" + phoneString + "&brand=" + brandname + "&code_length=4"

			resp, err := http.Get(url)
			if err != nil {
				log.Println("Error getting url: "+url, err)

				w.WriteHeader(http.StatusInternalServerError)
			} else {

				bodyBytes, err := ioutil.ReadAll(resp.Body)

				if err != nil {
					log.Println("Error convering body to bytes", err)

					w.WriteHeader(http.StatusInternalServerError)
				} else {

					var Response NexmoReqResponse
					err := json.Unmarshal(bodyBytes, &Response)
					if err != nil {
						log.Println("Error unmarshalling JSON to req rsponse nexmo")

						w.WriteHeader(http.StatusInternalServerError)
					} else {

						RequestID := Response.RequestID
						fmt.Fprintln(w, RequestID)

						w.WriteHeader(http.StatusInternalServerError)

					}

				}
			}
		} else if !ok {
			fmt.Fprintln(w, "Wrong or nil api key")

			w.WriteHeader(http.StatusUnauthorized)
		}
	}

}

func Verify2(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		log.Println("Err parsing form ", err)

		w.WriteHeader(http.StatusInternalServerError)

	} else {

		apikey := r.FormValue("apikey")
		_, ok := Companies[apikey]

		if ok {
			reqID := r.FormValue("reqid")
			code := r.FormValue("code")

			url := "https://api.nexmo.com/verify/check/json?&api_key=6d52c704&api_secret=KfFCibpdpshkPpr2&request_id=" + reqID + "&code=" + code

			resp, err := http.Get(url)
			if err != nil {
				log.Println("Err getting url: ", url, err)

				w.WriteHeader(http.StatusInternalServerError)
			} else {
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					log.Println("Err conv body to bytes", err)

					w.WriteHeader(http.StatusInternalServerError)
				} else {

					var CodeResp NexmoCodeVerResponse
					err := json.Unmarshal(bodyBytes, &CodeResp)
					if err != nil {
						log.Println("Err unmarshalling", err)
						w.WriteHeader(http.StatusInternalServerError)
					} else {
						w.WriteHeader(http.StatusOK)
					}
				}
			}
		} else if !ok {
			fmt.Fprintln(w, "Wrong or nil API key")

			w.WriteHeader(http.StatusUnauthorized)
		}
	}
}

func SaveToDB(a map[string]Company) error {

	b := new(bytes.Buffer)

	e := gob.NewEncoder(b)

	// Encoding the map
	err := e.Encode(a)
	if err != nil {
		return err
	}

	file, err2 := os.OpenFile("companies.db", os.O_CREATE|os.O_RDWR, 0655)

	if err2 != nil {
		return err2
	}

	_, err3 := file.Write(b.Bytes())
	if err3 != nil {
		return err3
	}

	file.Close()

	log.Println("Saved To DB")
	return nil
}

func LoadDB() (map[string]Company, error) {

	file, err1 := os.OpenFile("companies.db", os.O_CREATE|os.O_RDWR, 0655)
	if err1 != nil {
		return nil, err1
	}

	var decodedMap map[string]Company
	d := gob.NewDecoder(file)

	// Decoding the serialized data
	err4 := d.Decode(&decodedMap)
	if err4 != nil {
		return nil, err4
	}

	file.Close()
	return decodedMap, nil
}
