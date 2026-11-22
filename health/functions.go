package health

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
)

var startTime = time.Now()

// CheckDatabaseHealth pings the database or calls sp_HealthCheck
func CheckDatabaseHealth(db *sql.DB) string {
	if db == nil {
		return "not configured"
	}

	if err := db.Ping(); err != nil {
		return "disconnected"
	}

	// Verify via stored procedure
	var status string
	var serverTime string
	err := db.QueryRow("CALL sp_HealthCheck()").Scan(&status, &serverTime)
	if err != nil {
		return "connected (stored procedure check skipped)"
	}

	return fmt.Sprintf("%s (%s)", status, serverTime)
}

// HealthCheckHandler returns public health check info without requiring any Bearer token
func HealthCheckHandler(db *sql.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		dbStatus := "not configured"
		if db != nil {
			if err := db.Ping(); err != nil {
				dbStatus = "disconnected"
			} else {
				dbStatus = "connected"
			}
		}

		uptimeDuration := time.Since(startTime).Round(time.Second)

		return c.Status(fiber.StatusOK).JSON(HealthStatus{
			Status:    "ok",
			Database:  dbStatus,
			Timestamp: time.Now(),
			Uptime:    uptimeDuration.String(),
		})
	}
}
