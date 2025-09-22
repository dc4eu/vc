package openid4vp

type Context struct {
	Nonce                string                   `json:"nonce" bson:"nonce" validate:"required"`
	ID                   string                   `json:"id" bson:"id" validate:"required"`
	AuthorizationRequest *AuthorizationRequest_v2 `json:"authorization" bson:"authorization" validate:"required"`
}
