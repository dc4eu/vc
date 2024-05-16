package representations

import "time"

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoggedinReply struct {
	Username     string    `json:"username" binding:"required"`
	LoggedInTime time.Time `json:"logged_in_time" binding:"required"` //time.Time encoded to JSON will use the RFC3339 format by default, which is essentially ISO 8601 (e.g., "2024-05-09T14:00:00Z"
}

type PortalRequest struct {
	DocumentType            string `json:"document_type" binding:"required"`
	AuthenticSource         string `json:"authentic_source" binding:"required"`
	AuthenticSourcePersonId string `json:"authentic_source_person_id" binding:"required"`
}

type MockNextRequest struct {
	PortalRequest
}
