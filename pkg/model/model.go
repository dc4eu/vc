package model

import "time"

// Meta is a generic type for metadata
type Meta struct {
	UploadID     string    `json:"upload_id" bson:"upload_id"`
	Timestamp    time.Time `json:"timestamp" bson:"timestamp"`
	DocumentType string    `json:"document_type"`
}
