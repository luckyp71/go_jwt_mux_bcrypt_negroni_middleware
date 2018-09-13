package models

import (
	jwt "github.com/dgrijalva/jwt-go"
)

type UserClaims struct {
	jwt.StandardClaims
}
