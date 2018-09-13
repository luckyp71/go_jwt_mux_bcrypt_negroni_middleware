package headers

import (
	"net/http"
)

//Success is used to inform that particular service invocation gives success response
func Success(res http.ResponseWriter) {
	res.Header().Set("Content-Type", "application/json")
	res.Header().Add("Access-Control-Expose-Headers", "Response-Code, Response-Desc")
	res.Header().Set("Response-Code", "Success")
	res.Header().Set("Response-Desc", "00")
	res.WriteHeader(200)
}

//NotFound is used to inform that data is not found
func NotFound(res http.ResponseWriter) {
	res.Header().Set("Content-Type", "application/json")
	res.Header().Add("Access-Control-Expose-Headers", "Response-Code, Response-Desc")
	res.Header().Set("Response-Code", "Data not found")
	res.Header().Set("Response-Desc", "01")
	res.WriteHeader(404)
}

//ServerError is used to inform that server is error
func ServerError(res http.ResponseWriter) {
	res.Header().Set("Content-Type", "application/json")
	res.Header().Add("Access-Control-Expose-Headers", "Response-Code, Response-Desc")
	res.Header().Set("Response-Code", "Internal server error")
	res.Header().Set("Response-Desc", "02")
	res.WriteHeader(500)
}

//AlreadyExists
func AlreadyExists(res http.ResponseWriter) {
	res.Header().Set("Content-Type", "application/json")
	res.Header().Add("Access-Control-Expose-Headers", "Response-Code, Response-Desc")
	res.Header().Set("Response-Code", "Data already exists")
	res.Header().Set("Response-Desc", "03")
	res.WriteHeader(400)
}

//AuthFailed is used to inform when user provide wrong credential
func AuthFailed(res http.ResponseWriter) {
	res.Header().Set("Content-Type", "application/json")
	res.Header().Add("Access-Control-Expose-Headers", "Response-Code, Response-Desc")
	res.Header().Set("Response-Code", "Authentication failed")
	res.Header().Set("Response-Desc", "04")
	res.WriteHeader(400)
}

//Unauthorized is used to inform when someone has no access to particular route
func Unauthorized(res http.ResponseWriter) {
	res.Header().Set("Content-Type", "application/json")
	res.Header().Add("Access-Control-Expose-Headers", "Response-Code, Response-Desc")
	res.Header().Set("Response-Code", "Unauthorized")
	res.Header().Set("Response-Desc", "05")
	res.WriteHeader(401)
}
