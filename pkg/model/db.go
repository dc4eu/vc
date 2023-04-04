package model

// Transaction is the transaction model
type Transaction struct {
	ID            string `json:"id" bson:"_id"`
	TransactionID string `json:"transaction_id" bson:"transaction_id"`
	KeyLabel      string `json:"key_label" bson:"key_label"`
	KeyType       string `json:"key_type" bson:"key_type"`
	HashType      string `json:"hash_type" bson:"hash_type"`
}
