package main

import (
	"encoding/json"
	"fmt"
	h "go_jwt_mux_bcrypt_negroni_middleware/headers"
	m "go_jwt_mux_bcrypt_negroni_middleware/models"
	"net/http"

	"github.com/codegangsta/negroni"
	jwt "github.com/dgrijalva/jwt-go"
	jwtreq "github.com/dgrijalva/jwt-go/request"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"golang.org/x/crypto/bcrypt"
)

var db *gorm.DB
var e error

func main() {
	db, e = gorm.Open("postgres", "host=localhost port=5432 user=postgres password=pratama dbname=postgres sslmode=disable")
	if e != nil {
		fmt.Println(e)
	} else {
		fmt.Println("Connection Established")
	}
	defer db.Close()
	db.SingularTable(false)
	db.AutoMigrate(&m.UserToken{}, m.User{})

	router := mux.NewRouter()
	router.Path("/").HandlerFunc(HomeHandler)

	tokenRoute := router.PathPrefix("/token").Subrouter()
	tokenRoute.HandleFunc("", GenerateUserToken).Methods("POST")

	authMiddleware := mux.NewRouter()
	router.PathPrefix("/apiname").Handler(negroni.New(
		negroni.HandlerFunc(JwtMiddleware),
		negroni.Wrap(authMiddleware),
	))

	apiRoute := authMiddleware.PathPrefix("/apiname").Subrouter()
	apiRoute.HandleFunc("/register", RegisterUser).Methods("POST")
	apiRoute.HandleFunc("/login", LoginHandler).Methods("POST")
	apiRoute.HandleFunc("/landingpage", LandingHandler).Methods("GET")
	http.ListenAndServe(":8080", router)
}

//HomeHandler can be invoked by anyone
func HomeHandler(res http.ResponseWriter, req *http.Request) {
	h.Success(res)
	res.Write([]byte(`{"message":"Welcome home"}`))
}

//GenerateUserToken is used to generate token
func GenerateUserToken(res http.ResponseWriter, req *http.Request) {
	var userToken m.UserToken
	var _ = json.NewDecoder(req.Body).Decode(&userToken)

	if userToken.TokenUser == "" || userToken.Password == "" {
		h.AuthFailed(res)
		res.Write([]byte(`{"message":"Bad request!!!"}`))
	} else {

		claims := m.UserClaims{
			jwt.StandardClaims{
				Issuer: userToken.Issuer,
			},
		}

		encryptedPassword, e := bcrypt.GenerateFromPassword([]byte(userToken.Password), bcrypt.DefaultCost)
		if e != nil {
			fmt.Println(e)
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		ss, err := token.SignedString(encryptedPassword)

		if err != nil {
			h.ServerError(res)
			res.Write([]byte(`{"message":"` + err.Error() + `"}`))
		} else {
			if e := db.Debug().Where("token_user = ?", userToken.TokenUser).First(&userToken).Error; e != nil {
				userToken.Token = ss
				userToken.Password = string(encryptedPassword)
				db.Create(&userToken)
				h.Success(res)
				res.Write([]byte(`{"Token":"` + ss + `"}`))
			} else {
				fmt.Println(e)
				h.AlreadyExists(res)
				res.Write([]byte(`{"message":"Token is already exists"}`))
			}
		}
	}
}

//JwtMiddleware as auth handler
func JwtMiddleware(res http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	var claims m.UserClaims
	var userToken m.UserToken
	tokenString := req.Header.Get("Authorization")
	fmt.Println("Authenticating....")
	if e := db.Where("token = ?", tokenString).First(&userToken).Error; e != nil {
		h.NotFound(res)
		res.Write([]byte(`{"message":"Bad request!!!!! your token is invalid!!!!!!"}`))
	} else {
		token, err := jwtreq.ParseFromRequestWithClaims(req, jwtreq.AuthorizationHeaderExtractor, &claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(userToken.Password), nil
		})
		if err != nil {
			fmt.Println(err)
			h.ServerError(res)
			res.Write([]byte(`{"message":"Failed to parse token"}`))

		} else if !token.Valid {
			h.Unauthorized(res)
			res.Write([]byte(`{"message":"Invalid token"}`))
		} else {
			next(res, req)
		}
	}
}

//RegisterUser is used to register user
func RegisterUser(res http.ResponseWriter, req *http.Request) {
	var user m.User
	var _ = json.NewDecoder(req.Body).Decode(&user)
	fmt.Println("Username is", user.Username)
	if e := db.Debug().Where("username = ?", user.Username).First(&user).Error; e != nil {
		encryptedPassword, e := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if e != nil {
			fmt.Println(e)
		}
		user.Password = string(encryptedPassword)
		db.Create(&user)
		h.Success(res)
	} else {
		h.AlreadyExists(res)
	}
}

//LoginHandler is used to login in frontend app
func LoginHandler(res http.ResponseWriter, req *http.Request) {
	var user m.User
	var _ = json.NewDecoder(req.Body).Decode(&user)
	userPassword := user.Password
	if e := db.Where("username =?", user.Username).First(&user).Error; e != nil {
		fmt.Println("Not Found")
	} else {
		if e := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userPassword)); e != nil {
			fmt.Println(e)
			h.AuthFailed(res)
			res.Write([]byte(`{"Response-Description":"Given password for username: ` + user.Username + ` is not match"}`))
		} else {
			h.Success(res)
			res.Write([]byte(`{"message":"You are authenticated user"}`))
		}
	}
}

//LandingHandler is used to show data after user provide its credential in frontend app
func LandingHandler(res http.ResponseWriter, req *http.Request) {
	h.Success(res)
	res.Write([]byte(`{"message":"Landing Page Data"}`))
}
