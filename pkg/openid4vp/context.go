package openid4vp

type Context struct {
	ID                   string                   `json:"id" bson:"id" validate:"required"`
	AuthorizationRequest *AuthorizationRequest_v2 `json:"authorization" bson:"authorization" validate:"required"`
}
