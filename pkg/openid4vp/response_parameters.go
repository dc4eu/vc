package openid4vp

type ResponseParameters struct {
	//VPToken REQUIRED. The structure of this parameter depends on the query language used to request the presentations in the Authorization Request:
	VPToken string `json:"vp_token,omitempty" bson:"vp_token" validate:"omitempty,required_if=ResponseType vp_token"`

	Code  string `json:"code,omitempty" bson:"code"`
	ISS   string `json:"iss,omitempty" bson:"iss"`
	State string `json:"state,omitempty" bson:"state"`
}
