package main

import (
	"encoding/json"
	"fmt"
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

type User struct {
	Username string `gorm:"primary_key" json:"username"`
	Password string `json"password"`
	Token    string `json:"token"`
	Issuer   string `json:"issuer"`
}

type UserClaims struct {
	jwt.StandardClaims
}

func main() {
	db, e = gorm.Open("postgres", "host=localhost port=5432 user=postgres password=pratama dbname=postgres sslmode=disable")
	if e != nil {
		fmt.Println(e)
	} else {
		fmt.Println("Connection Established")
	}
	defer db.Close()
	db.SingularTable(false)
	db.AutoMigrate(&User{})

	router := mux.NewRouter()
	router.Path("/").HandlerFunc(HomeHandler)

	tokenRoute := router.PathPrefix("/token").Subrouter()
	tokenRoute.HandleFunc("", GenerateUserToken).Methods("POST")

	authMiddleware := mux.NewRouter()
	router.PathPrefix("/apiname").Handler(negroni.New(
		negroni.HandlerFunc(JwtMiddleware),
		negroni.Wrap(authMiddleware),
	))

	authRoutes := authMiddleware.PathPrefix("/apiname").Subrouter()
	authRoutes.HandleFunc("/landingpage", LandingHandler).Methods("GET")
	http.ListenAndServe(":8080", router)
}

//HomeHandler can be invoked by anyone
func HomeHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Add("Access-Control-Expose-Headers", "Response-Code, Response-Desc")
	res.Header().Set("Content-Type", "application/json")
	res.Header().Set("Response-Code", "00")
	res.Header().Set("Response-Desc", "Success")
	res.WriteHeader(200)
	res.Write([]byte(`{"message":"Welcome home"}`))
}

//GenerateUserToken is used to generate token
func GenerateUserToken(res http.ResponseWriter, req *http.Request) {
	var user User
	res.Header().Set("Content-Type", "application/json")
	res.Header().Add("Access-Control-Expose-Headers", "Response-Code, Response-Desc")

	var _ = json.NewDecoder(req.Body).Decode(&user)

	if user.Username == "" || user.Password == "" {
		res.Header().Set("Response-Code", "04")
		res.Header().Set("Response-Desc", "Please provide user credential properly!!!!")
		res.WriteHeader(400)
		res.Write([]byte(`{"message":"Bad request!!!"`))
	} else {

		claims := UserClaims{
			jwt.StandardClaims{
				Issuer: user.Issuer,
			},
		}

		hash, e := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if e != nil {
			fmt.Println(e)
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		ss, err := token.SignedString(hash)

		if err != nil {
			res.Header().Set("Response-Code", "02")
			res.Header().Set("Response-Desc", "Internal server error")
			res.WriteHeader(500)
			res.Write([]byte(`{"message":"` + err.Error() + `"}`))
		} else {
			if e := db.Debug().Where("username = ?", user.Username).First(&user).Error; e != nil {
				res.Header().Set("Response-Code", "00")
				res.Header().Set("Response-Desc", "Success")
				user.Token = ss
				user.Password = string(hash)
				db.Create(&user)
				res.WriteHeader(200)
				res.Write([]byte(`{"Token":"` + ss + `"}`))
			} else {
				fmt.Println(e)
				res.Header().Set("Response-Code", "04")
				res.Header().Set("Response-Desc", "Username is already exists!!!!!!!!")
				res.WriteHeader(400)
				res.Write([]byte(`{"message":"Bad request!!!"}`))
			}
		}
	}
}

//JwtMiddleware as auth handler
func JwtMiddleware(res http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	var claims UserClaims
	var user User
	res.Header().Set("Content-Type", "application/json")
	res.Header().Add("Access-Control-Expose-Headers", "Response-Code, Response-Desc")
	var _ = json.NewDecoder(req.Body).Decode(&user)
	//	userPassword := user.Password
	tokenString := req.Header.Get("Authorization")
	fmt.Println("Authenticating....")
	if e := db.Where("token = ?", tokenString).First(&user).Error; e != nil {
		res.Header().Set("Response-Code", "01")
		res.Header().Set("Response-Desc", "Bad request!!!!! your token is invalid!!!!!!")
		res.WriteHeader(400)
		res.Write([]byte(`{"message":"Bad request!!!!! your token is invalid!!!!!!"}`))
	} else {
		token, err := jwtreq.ParseFromRequestWithClaims(req, jwtreq.AuthorizationHeaderExtractor, &claims, func(token *jwt.Token) (interface{}, error) {
			fmt.Println([]byte(user.Password))
			return []byte(user.Password), nil
		})
		if err != nil {
			fmt.Println(err)
			res.Header().Set("Response-Code", "02")
			res.Header().Set("Response-Desc", "Internal server error")
			res.WriteHeader(500)
			res.Write([]byte(`{"message":"Failed to parse token"}`))

		} else if !token.Valid {
			res.Header().Set("Response-Code", "03")
			res.Header().Set("Response-Desc", "Unauthorized")
			res.WriteHeader(401)
			res.Write([]byte(`{"message":"Invalid token"}`))

		} else {
			next(res, req)
		}
	}
}

//LandingHandler
func LandingHandler(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	res.Header().Set("Response-Code", "00")
	res.Header().Set("Response-Desc", "Success")
	res.WriteHeader(200)
	res.Write([]byte(`{"message":"Landing Page Data"}`))
}
