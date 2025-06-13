package openid4vci

type AuthorizationConsentRequest struct {
	State string `json:"state"`
	Code  string `json:"code"`
}
type AuthorizationConsentReply struct{}

type AuthorizationConsentLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type AuthorizationConsentLoginReply struct{}
