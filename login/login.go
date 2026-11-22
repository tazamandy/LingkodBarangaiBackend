package login

// Login represents the credentials required to log in
type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// UserData represents the user information retrieved from the database
type UserData struct {
	ID        int    `json:"id"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	Email     string `json:"email"`
	Password  string `json:"-"`
	Roletype  string `json:"roletype"`
}

// LoginResponse represents the response containing "log in successful" and bearer token
type LoginResponse struct {
	Message     string `json:"message"`
	BearerToken string `json:"bearer_token"`
	TokenType   string `json:"token_type"`
}
