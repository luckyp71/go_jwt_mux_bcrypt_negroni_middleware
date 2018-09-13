package models

type UserToken struct {
	TokenUser string `gorm:"primary_key; type:varchar(100)" json:"token_user"`
	Password  string `gorm:"type:varchar(100)" json"password"`
	Token     string `gorm:"type:varchar(255)" json:"token"`
	Issuer    string `gorm:"type:varchar(50)" json:"issuer"`
}
