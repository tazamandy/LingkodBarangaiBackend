package register

// Register represents all the fields needed to register a new user
type Register struct {
	Firstname    string `json:"firstname"`
	MiddleName   string `json:"middlename"`
	Lastname     string `json:"lastname"`
	Suffix       string `json:"suffix"`
	GenderId     int    `json:"genderid"`
	Religion     string `json:"religion"`
	Nationality  string `json:"nationality"`
	Roletype     string `json:"roletype"`
	HouseNumber  string `json:"housenumber"`
	Purok        string `json:"purok"`
	Barangay     string `json:"barangay"`
	Municipality string `json:"municipality"`
	Province     string `json:"province"`
	ZipCode      string `json:"zipcode"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	TotpSecret   string `json:"totp_secret,omitempty"`
}

// VerifyOTP represents payload when verifying authenticator app 30-second code
type VerifyOTP struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}
