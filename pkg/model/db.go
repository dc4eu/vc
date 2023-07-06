package model

// UnsignedDocument is the unsigned document model
type UnsignedDocument struct {
	Data string `json:"data" bson:"data"`
	TS   int64  `json:"ts" bson:"ts"`
}

// SignedDocument is the signed document model
type SignedDocument struct {
	Data       string `json:"data" bson:"data"`
	TS         int64  `json:"ts" bson:"ts"`
	SHA256Hash string `json:"sha256_hash" bson:"sha256_hash"`
}

// Document is the document model
type Document struct {
	TransactionID string            `json:"transaction_id" bson:"transaction_id"`
	Signed        *SignedDocument   `json:"signed" bson:"signed"`
	Unsigned      *UnsignedDocument `json:"unsigned" bson:"unsigned"`
	RevokedTS     int64             `json:"revoked_ts" bson:"revoked_ts"`
	LadokUID      string            `json:"ladok_uid" bson:"ladok_uid"`
}
