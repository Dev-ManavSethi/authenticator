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
	"strconv"
	"sync"

	"github.com/joho/godotenv"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	Companies      map[string]Company
	GlobalMutex    sync.Mutex
	DummyError     error
	WelcomeMessage string
)

type (
	Company struct {
		Name   string
		ID     string
		APIkey string
		Users  []User
	}

	User struct {
		Name          string
		ID            string
		Password      []byte
		Email         string
		Phone         int64
		PhoneVerified bool
		EmailVerified bool
		Address       Address
	}
	Address struct {
		Address1 string
		Address2 string
		City     string
		State    string
		Country  string
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

	DummyError = nil
	WelcomeMessage, DummyError = LoadHomeMessage()
	DummyError = nil

	err := godotenv.Load(".env")
	if err != nil {
		log.Println("Error loading .env", err)
	} else {
		log.Println("LOaded .env file")
	}

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
	mux.HandleFunc("/", Home)

	mux.HandleFunc("/generateAPIkey", GenAPIkey)

	mux.HandleFunc("/signup", Signup)
	//name, email, phone, password, fingerprint, iris, email_verified, phone_verified, address1, address2, city, state, country

	mux.HandleFunc("/email_login", EmailLogin)                  //email login
	mux.HandleFunc("/email_verify_request", EmailVerifyRequest) //email verify
	mux.HandleFunc("/email_verify_code", EmailVerifyCode)

	mux.HandleFunc("/phone_request_code", PhoneVerify)   //phone code request
	mux.HandleFunc("/phone_validate_code", PhoneVerify2) //phone code validation

	mux.HandleFunc("/company", CompanyData)
	mux.HandleFunc("/all", All) //get all db data (for admin)

	log.Println("Listening on " + os.Getenv("PORT"))
	log.Fatalln(http.ListenAndServe(":"+os.Getenv("PORT"), mux))
}

func CompanyData(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {

		apikey := r.FormValue("apikey")

		_, ok := Companies[apikey]

		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if ok {

			Company := Companies[apikey]

			jsonByte, err := json.Marshal(Company)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			} else {

				fmt.Fprintf(w, "application/json", string(jsonByte))
				w.WriteHeader(http.StatusOK)
			}
		}
	}
}

func EmailVerifyCode(w http.ResponseWriter, r *http.Request) {

}

func EmailVerifyRequest(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {

		// email := r.FormValue("email")
		apikey := r.FormValue("apikey")

		_, ok := Companies[apikey]

		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if ok {

		}
	}
}

func All(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {

		adminkey := r.FormValue("adminkey")
		if adminkey != os.Getenv("ADMIN_KEY") {
			w.WriteHeader(http.StatusUnauthorized)
		} else {

			for apikey, company := range Companies {
				fmt.Fprintln(w, apikey, " : ", company.Name, " ", company.ID, " ")
				for index, user := range company.Users {
					fmt.Fprintln(w, index+1, " ", user.Name, " ", user.ID, " ", user.Email, " ", user.EmailVerified, " ", user.Phone, " ", user.PhoneVerified, " ", user.Address.Address1, " ", user.Address.Address2, " ", user.Address.City, " ", user.Address.State, " ", user.Address.Country)
					fmt.Fprintln(w, "---------------------------------------------------------------------------------------------------")

				}

				fmt.Fprintln(w, "")
				fmt.Fprintln(w, "#####################################################################################################################")
				fmt.Fprintln(w, "#####################################################################################################################")

				fmt.Fprintln(w, "")
			}
		}

	}

}

func Home(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fmt.Fprintln(w, WelcomeMessage)
}

func GenAPIkey(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusBadRequest)
	} else {

		err := r.ParseForm()
		if err != nil {
			log.Println("Error parsing form", err)
			w.WriteHeader(http.StatusInternalServerError)
		} else {

			name := r.FormValue("name")

			for _, company := range Companies {
				if company.Name == name {

					w.WriteHeader(http.StatusAlreadyReported)
					return
				}
			}

			uuid := uuid.NewV4()

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
				return
			}

			response := `{apikey:` + hashString + `name:` + name + `company_id:` + id + `}`

			fmt.Fprintf(w, "application/json", response)

			w.WriteHeader(http.StatusCreated)

			//save to db file

		}
	}
}

func EmailLogin(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

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
						w.WriteHeader(http.StatusAccepted)
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

			w.WriteHeader(http.StatusUnauthorized)
		}
	}

}

func Signup(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Println("Error parsing form ", err)
		w.WriteHeader(http.StatusInternalServerError)
	} else {

		email := r.FormValue("email")
		pass := r.FormValue("password")
		name := r.FormValue("name")
		phone := r.FormValue("phone")

		phoneVerified := r.FormValue("phone_verified") == "true"
		EmailVerified := r.FormValue("email_verified") == "true"

		add1 := r.FormValue("address1")
		add2 := r.FormValue("address2")
		city := r.FormValue("city")
		state := r.FormValue("state")
		country := r.FormValue("country")
		uuid := uuid.NewV4()

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

				phone_int, err := strconv.Atoi(phone)
				if err != nil {
				}
				Company.Users = append(Company.Users, User{
					Name:     name,
					Email:    email,
					ID:       id,
					Password: HashedPass,
					Address: Address{
						Address1: add1,
						Address2: add2,
						City:     city,
						Country:  country,
						State:    state,
					},
					Phone:         int64(phone_int),
					PhoneVerified: phoneVerified,
					EmailVerified: EmailVerified,
				})

				GlobalMutex.Lock()
				Companies[apikey] = Company
				GlobalMutex.Unlock()

				log.Println("User signed up for company: " + Companies[apikey].Name)
				//save map to db

				err4 := SaveToDB(Companies)
				if err4 != nil {
					log.Println(err4)
					w.WriteHeader(http.StatusInternalServerError)
					return
				} else {

					w.WriteHeader(http.StatusCreated)
				}

			}
		}
	}
}

func PhoneVerify(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {

		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Println("Error parsing form", err)

		w.WriteHeader(http.StatusInternalServerError)
	} else {

		apikey := r.FormValue("apikey")

		_, ok := Companies[apikey]

		if ok {

			brandname := Companies[apikey].Name
			//log.Println(brandname)
			phoneString := r.FormValue("phone")

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

						w.WriteHeader(http.StatusOK)

					}

				}
			}
		} else if !ok {

			w.WriteHeader(http.StatusUnauthorized)
		}
	}

}

func PhoneVerify2(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

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
						w.WriteHeader(http.StatusAccepted)
					}
				}
			}
		} else if !ok {

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

func LoadHomeMessage() (string, error) {

	file, err := os.OpenFile("WelcomeMessage.txt", os.O_RDONLY, 0655)

	if err != nil {
		return "", err
	}

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}
