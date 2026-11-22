package register

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

// GenerateTOTPSecret generates a secure base32 encoded random secret for Google/MS Authenticator
func GenerateTOTPSecret() (string, error) {
	bytes := make([]byte, 20)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes), nil
}

// GenerateTOTPCode generates a 6-digit TOTP code based on a 30-second timeline (RFC 6238)
func GenerateTOTPCode(secret string, t time.Time) (string, error) {
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return "", err
		}
	}

	// 30-second timeline interval
	counter := uint64(t.Unix() / 30)

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	h := hmac.New(sha1.New, key)
	h.Write(buf)
	hash := h.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	truncatedHash := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	code := truncatedHash % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// VerifyTOTPCode checks if the code is valid within the 30-second timeline (+/- 1 step window)
func VerifyTOTPCode(secret, passcode string) bool {
	now := time.Now()
	for _, step := range []int64{0, -1, 1} {
		t := now.Add(time.Duration(step*30) * time.Second)
		expectedCode, err := GenerateTOTPCode(secret, t)
		if err == nil && expectedCode == passcode {
			return true
		}
	}
	return false
}

// GenerateTOTPURL creates the otpauth standard URL for QR code generation in authenticator apps
func GenerateTOTPURL(secret, email, issuer string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&period=30&digits=6",
		url.PathEscape(issuer),
		url.PathEscape(email),
		secret,
		url.QueryEscape(issuer),
	)
}

// HashPassword hashes plain text password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// ExecuteRegisterProcedure calls the SQL stored procedure with TOTP secret
func ExecuteRegisterProcedure(db *sql.DB, user *Register) error {
	query := `CALL sp_RegisterUser(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.Exec(
		query,
		user.Firstname,
		user.MiddleName,
		user.Lastname,
		user.Suffix,
		user.GenderId,
		user.Religion,
		user.Nationality,
		user.Roletype,
		user.HouseNumber,
		user.Purok,
		user.Barangay,
		user.Municipality,
		user.Province,
		user.ZipCode,
		user.Email,
		user.Password,
		user.TotpSecret,
	)

	return err
}

// RegisterHandler returns a Fiber handler for user registration with Authenticator setup
func RegisterHandler(db *sql.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req Register

		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		if strings.TrimSpace(req.Firstname) == "" ||
			strings.TrimSpace(req.Lastname) == "" ||
			strings.TrimSpace(req.Email) == "" ||
			strings.TrimSpace(req.Password) == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Firstname, Lastname, Email, and Password are required",
			})
		}

		hashedPassword, err := HashPassword(req.Password)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to hash password",
			})
		}
		req.Password = hashedPassword

		// Generate TOTP Secret para sa Authenticator Application (30 seconds timeline)
		totpSecret, err := GenerateTOTPSecret()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to generate authenticator secret",
			})
		}
		req.TotpSecret = totpSecret

		if err := ExecuteRegisterProcedure(db, &req); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		totpURL := GenerateTOTPURL(totpSecret, req.Email, "TazBackend")

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"message":     "User registered successfully. Add the secret to your Authenticator app.",
			"totp_secret": totpSecret,
			"totp_url":    totpURL,
			"timeline":    "30 seconds",
		})
	}
}

// VerifyOTPHandler verifies the 6-digit code from Google/Microsoft Authenticator
func VerifyOTPHandler(db *sql.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req VerifyOTP
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		var secret string
		err := db.QueryRow("SELECT totp_secret FROM users WHERE email = ? LIMIT 1", req.Email).Scan(&secret)
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

		if !VerifyTOTPCode(secret, req.Code) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid or expired authenticator code (must be entered within 30-second window)",
			})
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message": "Authenticator code verified successfully",
		})
	}
}
