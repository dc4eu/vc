package openid4vci

// NotificationRequest https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-notification-request
type NotificationRequest struct {
	NotificationID   string `json:"notification_id" validate:"required"`
	Event            string `json:"event" validate:"required,oneof=credential_accepted credential_failure credential_deleted"`
	EventDescription string `json:"event_description,omitempty"`
}
