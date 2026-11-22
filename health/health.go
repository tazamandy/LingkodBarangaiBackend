package health

import "time"

// HealthStatus represents the payload returned by the health check API
type HealthStatus struct {
	Status    string    `json:"status"`
	Database  string    `json:"database"`
	Timestamp time.Time `json:"timestamp"`
	Uptime    string    `json:"uptime"`
}
