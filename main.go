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
	AuthToken struct {
		UserID    string `json:"user_id"`
		CompanyID string `json:"company_id"`
		Signature string `json:"signature"`
	}

	LoginResponse struct {
		User      User   `json:"user"`
		AuthToken string `json:"auth_token"`
	}

	RestAPIresponse struct {
		StatusCode int `json:"status_code"`

		Error   string      `json:"error"`
		Data    interface{} `json:"data"`
		Message string      `json:"message"`
	}

	Company struct {
		Name       string   `json:"name"`
		ID         string   `json:"id"`
		APIkey     string   `json:"api_key"`
		Users      []User   `json:"users"`
		AuthTokens []string `json:"auth_tokens"`
	}

	User struct {
		Name          string   `json:"name"`
		ID            string   `json:"id"`
		Password      []byte   `json:"password"`
		Email         string   `json:"email"`
		Phone         int64    `json:"phone"`
		PhoneVerified bool     `json:"phone_verified"`
		EmailVerified bool     `json:"email_verified"`
		Address       Address  `json:"address"`
		AuthTokens    []string `json:"auth_tokens"`
	}
	Address struct {
		Address1 string `json:"address1"`
		Address2 string `json:"address2"`
		City     string `json:"city"`
		State    string `json:"state"`
		Country  string `json:"country"`
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

	mux.HandleFunc("/generateAPIkey", GenAPIkey) //signup for company

	mux.HandleFunc("/signup", Signup)
	//name, email, phone, password, fingerprint, iris, email_verified, phone_verified, address1, address2, city, state, country

	mux.HandleFunc("/email_verify_request", EmailVerifyRequest) //email verify //remaining
	mux.HandleFunc("/email_verify_code", EmailVerifyCode)       //remaining

	mux.HandleFunc("/phonelogin", PhoneVerifyRequest) //phone code request
	mux.HandleFunc("/phonelogin2", PhoneVerifyCode)   //phone code validation

	mux.HandleFunc("/email_login", EmailLogin) //email login
	mux.HandleFunc("/phone_login", PhoneLogin) //phone login

	mux.HandleFunc("/company", CompanyData) //get company data
	mux.HandleFunc("/user", UserData)       //get user data
	mux.HandleFunc("/all", All)             //get all db data (for admin)

	mux.HandleFunc("/verifyauth", VerifyAuth)

	log.Println("Listening on " + os.Getenv("PORT"))
	log.Fatalln(http.ListenAndServe(":"+os.Getenv("PORT"), mux))
}

func VerifyAuth(w http.ResponseWriter, r *http.Request) {

	var Response RestAPIresponse

	ResponseEncoder := json.NewEncoder(w)

	if r.Method == http.MethodGet {
		PrepareResponse(&Response, http.StatusBadRequest, "Sending GET request to /verifyAuth is not allowed", nil, "Send POST instead", w, ResponseEncoder)

	} else {

		err := r.ParseForm()
		if err != nil {

			PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Parsing POST form error", w, ResponseEncoder)
			return

		} else {

			apikey := r.FormValue("apikey")
			authtoken := r.FormValue("authtoken")

			_, ok := Companies[apikey]
			if !ok {
				PrepareResponse(&Response, http.StatusUnauthorized, "API key is nil or wrong", nil, "Check your API key again", w, ResponseEncoder)
				return
			}
			if ok {

				company_id := Companies[apikey].ID

				var AuthTokenValid bool = false

				for _, user := range Companies[apikey].Users {

					user_id := user.ID

					hash := sha256.New()
					_, err0 := hash.Write([]byte(user_id + "." + company_id + "." + os.Getenv("PRIVATE_KEY")))
					if err0 != nil {
						PrepareResponse(&Response, http.StatusInternalServerError, err0.Error(), nil, "Error creating auth token", w, ResponseEncoder)
						return
					}

					hashString := hex.EncodeToString(hash.Sum(nil))

					if hashString != authtoken {
						continue
					}
					if hashString == authtoken {

						AuthTokenValid = true
						PrepareResponse(&Response, http.StatusAccepted, "", nil, "Valid auth token", w, ResponseEncoder)
						return
					}

				}

				if AuthTokenValid == false {
					PrepareResponse(&Response, http.StatusNotAcceptable, "Invalid auth token", nil, "Invalid auth token", w, ResponseEncoder)
				}
			}

		}
	}

}

func UserData(w http.ResponseWriter, r *http.Request) {

	var Response RestAPIresponse

	ResponseEncoder := json.NewEncoder(w)

	err := r.ParseForm()
	if err != nil {
		PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Parsing POST form error", w, ResponseEncoder)
		return

	} else {

		apikey := r.FormValue("apikey")

		_, ok := Companies[apikey]

		if !ok {
			PrepareResponse(&Response, http.StatusUnauthorized, "Invalid API key", nil, "", w, ResponseEncoder)
			return
		}
		if ok {

			// name := r.FormValue("name")
			// id := r.FormValue("id")
			phone := r.FormValue("phone")
			// email := r.FormValue("email")

			if phone != "" {

				phone_int, err := strconv.Atoi(phone)
				if err != nil {
					PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error convering string phone to int", w, ResponseEncoder)
					return
				} else {

					Company := Companies[apikey]
					var UserFound bool = false
					var User User

					for _, user := range Company.Users {
						if user.Phone == int64(phone_int) {
							UserFound = true
							User = user
						}
					}

					if UserFound {

						PrepareResponse(&Response, http.StatusFound, "", User, "Here is the user data", w, ResponseEncoder)

					}
					if !UserFound {
						PrepareResponse(&Response, http.StatusNotFound, "User not found with given details", nil, "", w, ResponseEncoder)

					}

				}

			}
		}
	}
}

func PhoneLogin(w http.ResponseWriter, r *http.Request) {

	var Response RestAPIresponse

	ResponseEncoder := json.NewEncoder(w)

	err := r.ParseForm()
	if err != nil {
		PrepareResponse(&Response, http.StatusBadRequest, "Sending GET request is not allowed", nil, "Send POST instead", w, ResponseEncoder)

	} else {

		apikey := r.FormValue("apikey")

		_, ok := Companies[apikey]

		if !ok {
			PrepareResponse(&Response, http.StatusUnauthorized, "Invalid API key", nil, "Check your API key", w, ResponseEncoder)
			return
		}
		if ok {

			phone := r.FormValue("phone")
			phone_int, err := strconv.Atoi(phone)
			if err != nil {
				PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error converting string phone to integer", w, ResponseEncoder)

			} else {

				Company := Companies[apikey]

				var UserFound bool = false

				var User User

				for _, user := range Company.Users {
					if user.Phone == int64(phone_int) {
						UserFound = true
						User = user
						break
					}
				}

				if UserFound {

					hash := sha256.New()
					_, err := hash.Write([]byte(User.ID + "." + Companies[apikey].ID + "." + os.Getenv("PRIVATE_KEY")))

					if err != nil {
						PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error creating auth token", w, ResponseEncoder)
						return
					}
					LoginResponse := LoginResponse{
						User:      User,
						AuthToken: hex.EncodeToString(hash.Sum(nil)),
					}
					PrepareResponse(&Response, http.StatusAccepted, "", LoginResponse, "Send POST instead", w, ResponseEncoder)

				}
				if !UserFound {
					PrepareResponse(&Response, http.StatusNotFound, "Could not find user user", nil, "Could nt find user", w, ResponseEncoder)

				}

			}
		}
	}
}

func CompanyData(w http.ResponseWriter, r *http.Request) {

	var Response RestAPIresponse

	ResponseEncoder := json.NewEncoder(w)

	err := r.ParseForm()
	if err != nil {
		PrepareResponse(&Response, http.StatusBadRequest, "Sending GET request is not allowed", nil, "Send POST instead", w, ResponseEncoder)

	} else {

		apikey := r.FormValue("apikey")

		_, ok := Companies[apikey]

		if !ok {
			PrepareResponse(&Response, http.StatusUnauthorized, "invalid api key", nil, "", w, ResponseEncoder)

			return
		}
		if ok {

			Company := Companies[apikey]

			PrepareResponse(&Response, http.StatusOK, "", Company, "Hope you are having a good time in the company!", w, ResponseEncoder)

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

			var Companiess []Company
			for _, company := range Companies {

				Companiess = append(Companiess, company)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(Companiess)

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

func PrepareResponse(Response *RestAPIresponse, status_code int, err string, data interface{}, message string, w http.ResponseWriter, Encoder *json.Encoder) {

	Response.StatusCode = status_code
	Response.Error = err
	Response.Data = data
	Response.Message = message

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status_code)

	Encoder.Encode(*Response)
}

func GenAPIkey(w http.ResponseWriter, r *http.Request) {

	var Response RestAPIresponse

	ResponseEncoder := json.NewEncoder(w)

	if r.Method == http.MethodGet {
		PrepareResponse(&Response, http.StatusBadRequest, "Sending GET request to /generateAPIkey is not allowed", nil, "Send POST instead", w, ResponseEncoder)

	} else {

		err := r.ParseForm()
		if err != nil {

			PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Parsing POST form error", w, ResponseEncoder)
			return

		} else {

			name := r.FormValue("name")

			for _, company := range Companies {
				if company.Name == name {

					PrepareResponse(&Response, http.StatusAlreadyReported, err.Error(), nil, "Parsing POST form error", w, ResponseEncoder)

					return
				}
			}

			uuid := uuid.NewV4()

			id := uuid.String()

			h := sha256.New()
			h.Write([]byte(name + "." + id + "." + os.Getenv("PRIVATE_KEY")))

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

				PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error saving company to database", w, ResponseEncoder)

				return
			}

			type AllResponse struct {
				APIkey string `json:"apikey"`
				Name   string `json:"name"`
				ID     string `json:"company_id"`
			}

			var a AllResponse
			a.APIkey = hashString
			a.Name = name
			a.ID = id

			PrepareResponse(&Response, http.StatusCreated, "", a, "Company data created", w, ResponseEncoder)

		}
	}
}

func EmailLogin(w http.ResponseWriter, r *http.Request) {

	var Response RestAPIresponse

	ResponseEncoder := json.NewEncoder(w)

	if r.Method == http.MethodGet {
		PrepareResponse(&Response, http.StatusInternalServerError, "Error: Get method not allowed", nil, "Use POST instead", w, ResponseEncoder)

		return
	}

	err := r.ParseForm()
	if err != nil {
		PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Err parsing POST form", w, ResponseEncoder)

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

						PrepareResponse(&Response, http.StatusUnauthorized, err.Error(), nil, "Password not correct", w, ResponseEncoder)
						break
					}
					if err == nil {

						hash := sha256.New()
						hash.Write([]byte(user.ID + "." + Companies[apikey].ID + "." + os.Getenv("PRIVATE_KEY")))

						LoginResponse := LoginResponse{
							User:      user,
							AuthToken: hex.EncodeToString(hash.Sum(nil)),
						}
						PrepareResponse(&Response, http.StatusAccepted, "", LoginResponse, "Email and passwords match", w, ResponseEncoder)

					}
					if err != nil {
						PrepareResponse(&Response, http.StatusUnauthorized, err.Error(), nil, "????", w, ResponseEncoder)

						break
					}
				}
			}

			if !EmailFound {

				PrepareResponse(&Response, http.StatusUnauthorized, "Email incorrect", nil, "Email incorrect", w, ResponseEncoder)
			}
		}
		if !ok {

			PrepareResponse(&Response, http.StatusUnauthorized, "Invalid or nil API key", nil, "Check your API key", w, ResponseEncoder)
		}
	}

}

func Signup(w http.ResponseWriter, r *http.Request) {

	var Response RestAPIresponse
	ResponseEncoder := json.NewEncoder(w)

	err := r.ParseForm()
	if err != nil {
		PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error parsing POST form", w, ResponseEncoder)
		return
	} else {

		apikey := r.FormValue("apikey")

		email := r.FormValue("email")
		pass := r.FormValue("password")
		name := r.FormValue("name")
		phone := r.FormValue("phone")
		phone_int, err := strconv.Atoi(phone)
		if err != nil {
		}

		phoneVerified := r.FormValue("phone_verified") == "true"
		EmailVerified := r.FormValue("email_verified") == "true"

		add1 := r.FormValue("address1")
		add2 := r.FormValue("address2")
		city := r.FormValue("city")
		state := r.FormValue("state")
		country := r.FormValue("country")

		uuid := uuid.NewV4()

		id := uuid.String()

		_, ok := Companies[apikey]
		if !ok {
			PrepareResponse(&Response, http.StatusUnauthorized, "API key is nil or wrong", nil, "Check your API key again", w, ResponseEncoder)
			return
		}
		if ok {

			Company := Companies[apikey]

			for _, user := range Company.Users {

				if user.Email == email || user.Phone == int64(phone_int) {

					PrepareResponse(&Response, http.StatusAlreadyReported, "User already exists with same email or phone", nil, "Same as error", w, ResponseEncoder)
					return
				}
			}

			if pass == "" {
				PrepareResponse(&Response, http.StatusAlreadyReported, "Warning: Password is empty", nil, "Password is empty", w, ResponseEncoder)

			}

			HashedPass, err := bcrypt.GenerateFromPassword([]byte(pass), 10)

			if err != nil {
				PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error creating password hash", w, ResponseEncoder)
				if pass != "" {
					return
				}
			} else {

				Userr := User{
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
				}

				Company.Users = append(Company.Users, Userr)

				GlobalMutex.Lock()
				Companies[apikey] = Company
				GlobalMutex.Unlock()

				//save map to db

				err4 := SaveToDB(Companies)
				if err4 != nil {
					PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error saving data to database", w, ResponseEncoder)
					return

				} else {

					hash := sha256.New()
					_, err := hash.Write([]byte(Userr.ID + "." + Company.ID + "." + os.Getenv("PRIVATE_KEY")))
					if err != nil {
						PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "error creating auth token", w, ResponseEncoder)
						return
					}

					LoginResponse := LoginResponse{
						User:      Userr,
						AuthToken: hex.EncodeToString(hash.Sum(nil)),
					}

					PrepareResponse(&Response, http.StatusCreated, "", LoginResponse, "User created and saved to database", w, ResponseEncoder)

				}

			}
		}
	}
}

func PhoneVerifyRequest(w http.ResponseWriter, r *http.Request) {

	var Response RestAPIresponse
	ResponseEncoder := json.NewEncoder(w)

	if r.Method == http.MethodGet {

		PrepareResponse(&Response, http.StatusBadRequest, "GET req not allowed", nil, "Send POST instead", w, ResponseEncoder)
		return
	}

	err := r.ParseForm()
	if err != nil {
		PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "err parsing post form", w, ResponseEncoder)
		return
	} else {

		apikey := r.FormValue("apikey")

		_, ok := Companies[apikey]

		if ok {

			brandname := Companies[apikey].Name

			phoneString := r.FormValue("phone")

			if len(phoneString) != 12 {

				PrepareResponse(&Response, http.StatusBadRequest, "Length of phone number is not 12", nil, "Phone number format is AB1234567890 where AB is country code", w, ResponseEncoder)
				return
			}
			phone_int, err := strconv.Atoi(phoneString)
			if err != nil {
				PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error convering string to int (phone number). Might be in wrong format", w, ResponseEncoder)
				return
			}

			//check if phone exists

			var PhoneExists bool = true
			for _, user := range Companies[apikey].Users {

				if user.Phone == int64(phone_int) {
					PhoneExists = true
				}
			}

			if !PhoneExists {
				//signup

				var jsonStr = []byte(`{"phone":"` + phoneString + `", "apikey": ` + apikey + `}`)
				resp, err := http.Post("/sigup", "application/json", bytes.NewBuffer(jsonStr))
				if err != nil {
					PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error signing up user (send POST to /signup)", w, ResponseEncoder)
					return
				}

				if resp.StatusCode != http.StatusCreated {
					PrepareResponse(&Response, resp.StatusCode, "Error creating new user", nil, "Error signing up user (different ststus code than 201 from server)", w, ResponseEncoder)
					return
				}
			}

			//send code to phone
			url := "https://api.nexmo.com/verify/json?api_key=6d52c704&api_secret=KfFCibpdpshkPpr2&number=" + phoneString + "&brand=" + brandname + "&code_length=4"

			resp, err := http.Get(url)
			if err != nil {
				PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error getting response from SMS server", w, ResponseEncoder)
				return
			} else {

				bodyBytes, err := ioutil.ReadAll(resp.Body)

				if err != nil {

					PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error reading response body from SMS server", w, ResponseEncoder)
					return
				} else {

					var NexmoResponse NexmoReqResponse
					err := json.Unmarshal(bodyBytes, &NexmoResponse)
					if err != nil {
						PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), string(bodyBytes), "Error proccessing response from SMS server", w, ResponseEncoder)
						return
					} else {

						PrepareResponse(&Response, http.StatusOK, "", NexmoResponse, "Keep the Request ID. Send POST to /phonelogin2 with req id and code", w, ResponseEncoder)

					}

				}
			}

		} else if !ok {
			PrepareResponse(&Response, http.StatusUnauthorized, "Invalid or nil API key", nil, "Same as error", w, ResponseEncoder)
		}
	}

}

func PhoneVerifyCode(w http.ResponseWriter, r *http.Request) {

	var Response RestAPIresponse
	ResponseEncoder := json.NewEncoder(w)

	if r.Method == http.MethodGet {

		PrepareResponse(&Response, http.StatusBadRequest, "GET not allowed", nil, "send POST instead", w, ResponseEncoder)
	}

	err := r.ParseForm()
	if err != nil {

		PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error parsing post form", w, ResponseEncoder)
		return
	} else {

		apikey := r.FormValue("apikey")
		_, ok := Companies[apikey]

		if ok {
			reqID := r.FormValue("reqid")
			code := r.FormValue("code")
			phone := r.FormValue("phone")

			phone_int, err := strconv.ParseInt(phone, 10, 64)
			if err != nil {
				PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error converting string to int64. Please check if phone  number format is correct", w, ResponseEncoder)
				return
			}

			url := "https://api.nexmo.com/verify/check/json?&api_key=6d52c704&api_secret=KfFCibpdpshkPpr2&request_id=" + reqID + "&code=" + code

			resp, err := http.Get(url)
			if err != nil {
				PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error getting reposne from SMS server", w, ResponseEncoder)
				return
			} else {
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error proccessing body", w, ResponseEncoder)
					return
				} else {

					var CodeResp NexmoCodeVerResponse
					err := json.Unmarshal(bodyBytes, &CodeResp)
					if err != nil {
						PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error marshalling body of response to proper struct", w, ResponseEncoder)
						return
					} else {
						//find user and send
						var User User
						for _, user := range Companies[apikey].Users {
							if user.Phone == int64(phone_int) {
								User = user
							}
						}

						hash := sha256.New()
						_, err := hash.Write([]byte(User.ID + "." + Companies[apikey].ID + "." + os.Getenv("PRIVATE_KEY")))
						if err != nil {
							PrepareResponse(&Response, http.StatusInternalServerError, err.Error(), nil, "Error creating Auth token", w, ResponseEncoder)
							return

						}

						var LoginResponse LoginResponse
						LoginResponse.User = User
						LoginResponse.AuthToken = hex.EncodeToString(hash.Sum(nil))

						PrepareResponse(&Response, http.StatusAccepted, "", LoginResponse, "Phone Verified successfully", w, ResponseEncoder)

					}
				}
			}
		} else if !ok {
			PrepareResponse(&Response, http.StatusUnauthorized, "Invalid or nil API key", nil, "", w, ResponseEncoder)

		}
	}
}

func SaveToDB(a map[string]Company) error {

	log.Println("Saving companies to db")
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
