package model

//// PDFDocument is the unsigned document model
//type PDFDocument struct {
//	Data       string `json:"data" bson:"data" redis:"data"`
//	TS         int64  `json:"ts" bson:"ts" redis:"data"`
//	SHA256Hash string `json:"sha256_hash" bson:"sha256_hash" redis:"sha256_hash"`
//}

// Document is the document model
type Document struct {
	TransactionID string `json:"transaction_id" bson:"transaction_id"`
	//Signed        string `json:"signed" bson:"signed"`
	//Unsigned      string `json:"unsigned" bson:"unsigned"`
	Data      string `json:"data" bson:"data"`
	RevokedTS int64  `json:"revoked_ts" bson:"revoked_ts"`
	ModifyTS  int64  `json:"modify_ts" bson:"modify_ts"`
}
