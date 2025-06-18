package model

// Authorization is the model for the authorization token in the database
type Authorization struct {
	Scope               string    `json:"scope" bson:"scope" validate:"required"`
	Code                string    `json:"code" bson:"code"`
	RequestURI          string    `json:"request_uri" bson:"request_uri" validate:"required"`
	RedirectURI         string    `json:"redirect_url" bson:"redirect_url" validate:"required"`
	IsUsed              bool      `json:"is_used" bson:"is_used"`
	State               string    `json:"state"`
	ClientID            string    `json:"client_id" bson:"client_id" validate:"required"`
	ExpiresAt           int64     `json:"expires_at" bson:"expires_at" validate:"required"`
	CodeChallenge       string    `json:"code_challenge" bson:"code_challenge" validate:"required"`
	CodeChallengeMethod string    `json:"code_challenge_method" bson:"code_challenge_method" validate:"required,oneof=S256 plain"`
	LastUsed            int64     `json:"last_used" bson:"last_used"`
	SavedAt             int64     `json:"saved_at" bson:"saved_at"`
	Consent             bool      `json:"consent" bson:"consent"`                       // Indicates if the user has given consent for the authorization
	Identity            *Identity `json:"identity,omitempty" bson:"identity,omitempty"` // Optional identity information associated with the authorization
	Token               *Token    `json:"token,omitempty" bson:"token,omitempty"`       // Optional token information associated with the authorization
}

type Token struct {
	AccessToken string `json:"access_token" bson:"access_token" validate:"required"`
	ExpiresAt   int64  `json:"expires_at" bson:"expires_at" validate:"required"`
}

// OAuthUsers is the model for the OAuth users in the database
type OAuthUsers struct {
	Username string    `json:"username" bson:"username" validate:"required"`
	Password string    `json:"password" bson:"password" validate:"required"`
	Identity *Identity `json:"identity" bson:"identity" validate:"required"`
}

type CodeChallenge struct {
	CodeChallenge       string `json:"code_challenge" bson:"code_challenge" validate:"required"`
	CodeChallengeMethod string `json:"code_challenge_method" bson:"code_challenge_method" validate:"required,oneof=S256 plain"`
	LastUsed            int64  `json:"last_used" bson:"last_used"`
}
