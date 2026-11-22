package forgotpassword

// ForgotPasswordRequest represents payload when initiating password reset
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

// VerifyOTPRequest represents payload when verifying the 30-second Authenticator code
type VerifyOTPRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// ResetPasswordRequest represents payload to reset the password with Authenticator code
type ResetPasswordRequest struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}
