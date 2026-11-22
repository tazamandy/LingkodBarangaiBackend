package forgotpassword

import (
	"database/sql"
	"strings"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
	"tazbackend/register"
)

// HashPassword hashes the new plain text password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// ExecuteGetUserTOTPProcedure calls stored procedure to fetch user's TOTP secret
func ExecuteGetUserTOTPProcedure(db *sql.DB, email string) (string, error) {
	query := `CALL sp_GetUserTOTPSecret(?)`
	var secret string
	err := db.QueryRow(query, email).Scan(&secret)
	return secret, err
}

// ExecuteResetPasswordProcedure calls the SQL stored procedure sp_ResetPassword
func ExecuteResetPasswordProcedure(db *sql.DB, email, hashedPassword string) error {
	query := `CALL sp_ResetPassword(?, ?)`
	_, err := db.Exec(query, email, hashedPassword)
	return err
}

// RequestForgotPasswordHandler checks if email exists and prompts user for Authenticator code
func RequestForgotPasswordHandler(db *sql.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req ForgotPasswordRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		if strings.TrimSpace(req.Email) == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Email is required",
			})
		}

		_, err := ExecuteGetUserTOTPProcedure(db, req.Email)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "User with this email not found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message":  "User verified. Please enter the 6-digit code from your Authenticator app.",
			"timeline": "30 seconds",
		})
	}
}

// VerifyForgotOTPHandler verifies the Authenticator 6-digit code within the 30-second timeline
func VerifyForgotOTPHandler(db *sql.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req VerifyOTPRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		if strings.TrimSpace(req.Email) == "" || strings.TrimSpace(req.Code) == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Email and Authenticator Code are required",
			})
		}

		secret, err := ExecuteGetUserTOTPProcedure(db, req.Email)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "User not found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// I-verify gamit ang 30-second window TOTP code
		if !register.VerifyTOTPCode(secret, req.Code) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid or expired authenticator code (must be within 30-second window)",
			})
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message": "Authenticator code verified successfully. You may now reset your password.",
		})
	}
}

// ResetPasswordHandler verifies Authenticator code and updates password via Stored Procedure
func ResetPasswordHandler(db *sql.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req ResetPasswordRequest

		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		if strings.TrimSpace(req.Email) == "" ||
			strings.TrimSpace(req.Code) == "" ||
			strings.TrimSpace(req.NewPassword) == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Email, Authenticator Code, and NewPassword are required",
			})
		}

		secret, err := ExecuteGetUserTOTPProcedure(db, req.Email)
		if err != nil {
			if err == sql.ErrNoRows {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "User not found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// I-verify ang 30-second Authenticator code bago mag-reset
		if !register.VerifyTOTPCode(secret, req.Code) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid or expired authenticator code (must be within 30-second window)",
			})
		}

		hashedPassword, err := HashPassword(req.NewPassword)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to hash new password",
			})
		}

		if err := ExecuteResetPasswordProcedure(db, req.Email, hashedPassword); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message": "Password has been successfully reset",
		})
	}
}
