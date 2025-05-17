package model

// Authorization is the model for the authorization token in the database
type Authorization struct {
	Code                string `json:"code" bson:"code"`
	RequestURI          string `json:"request_uri" bson:"request_uri" validate:"required"`
	IsUsed              bool   `json:"is_used" bson:"is_used"`
	State               string `json:"state"`
	ClientID            string `json:"client_id" bson:"client_id" validate:"required"`
	CodeChallenge       string `json:"code_challenge" bson:"code_challenge" validate:"required"`
	CodeChallengeMethod string `json:"code_challenge_method" bson:"code_challenge_method" validate:"required,oneof=S256 plain"`
	LastUsed            int64  `json:"last_used" bson:"last_used"`
}

// OAuthUsers is the model for the OAuth users in the database
type OAuthUsers struct {
	Username string `json:"username" bson:"username" validate:"required"`
	Password string `json:"password" bson:"password" validate:"required"`
	//TODO: ev. flytta nedan till egen collection identities som har OAuthUsers._id som fk
	Identity *Identity `json:"identity" bson:"identity" validate:"required"`
}

type CodeChallenge struct {
	CodeChallenge       string `json:"code_challenge" bson:"code_challenge" validate:"required"`
	CodeChallengeMethod string `json:"code_challenge_method" bson:"code_challenge_method" validate:"required,oneof=S256 plain"`
	LastUsed            int64  `json:"last_used" bson:"last_used"`
}
