package main

type User struct {
	Dn       string
	Cn       string
	Name     string `json:"name"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

func NewUser(dn string, cn string) *User {
	return &User{
		Dn:       dn,
		Cn:       cn,
		Name:     "",
		Password: "",
		Email:    "",
	}
}
