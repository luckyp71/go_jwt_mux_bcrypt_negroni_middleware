package models

type User struct {
	UserID   uint64 `gorm:"primary_key" json:"user"`
	Username string `gorm:"type:varchar(100)" json:"username"`
	Password string `gorm:"type:varchar(100)" json:"password"`
}
