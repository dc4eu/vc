package openid4vp

type Context struct {
	Nonce                string         `json:"nonce" bson:"nonce" validate:"required"`
	ID                   string         `json:"id" bson:"id" validate:"required"`
	AuthorizationRequest *RequestObject `json:"authorization" bson:"authorization" validate:"required"`
}
