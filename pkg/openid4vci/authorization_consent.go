package openid4vci

type AuthorizationConsentRequest struct{}
type AuthorizationConsentReply struct{}

type AuthorizationConsentLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type AuthorizationConsentLoginReply struct{}
