package model

// Authorization is the model for the authorization token in the database
type Authorization struct {
	Code     string `json:"code" validate:"required"`
	IsUsed   bool   `json:"is_used" bson:"is_used"`
	State    string `json:"state"`
	ExpireAt int64  `json:"expire_at" bson:"expire_at" validate:"required"`
	//ClientType string `json:"client_type" validate:"required,oneof=confidential public"`
	ClientID            string `json:"client_id" bson:"client_id" validate:"required"`
	CodeChallenge       string `json:"code_challenge" bson:"code_challenge" validate:"required"`
	CodeChallengeMethod string `json:"code_challenge_method" bson:"code_challenge_method" validate:"required,oneof=S256 plain"`
	LastUsed            int64  `json:"last_used" bson:"last_used"`
}

// OAuthUsers is the model for the OAuth users in the database
type OAuthUsers struct {
	ClientID string `json:"client_id" bson:"client_id" validate:"required"`
}

type CodeChallenge struct {
	CodeChallenge       string `json:"code_challenge" bson:"code_challenge" validate:"required"`
	CodeChallengeMethod string `json:"code_challenge_method" bson:"code_challenge_method" validate:"required,oneof=S256 plain"`
	LastUsed            int64  `json:"last_used" bson:"last_used"`
}
