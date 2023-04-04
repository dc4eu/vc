package model

import "time"

var (
	//StatusOKWalletIssue status ok
	StatusOKWalletIssue = "STATUS_OK_wallet_issue"
	// StatusFailWalletIssue status fail
	StatusFailWalletIssue = "STATUS_FAIL_wallet_issue"
	// StatusOKWalletVerify status ok
	StatusOKWalletVerify = "STATUS_OK_wallet_verify"
	// StatusFailWalletVerify status fail
	StatusFailWalletVerify = "STATUS_FAIL_wallet_verify"
)

// Status type
type Status struct {
	Name                      string    `json:"name,omitempty"`
	SchoolName                string    `json:"school_name,omitempty"`
	Healthy                   bool      `json:"healthy,omitempty"`
	Status                    string    `json:"status,omitempty"`
	Message                   string    `json:"message,omitempty"`
	Timestamp                 time.Time `json:"timestamp,omitempty"`
	ClientCertificateWarnings []string  `json:"client_certificates,omitempty"`
}

// ManyStatus contains many status objects
type ManyStatus []*Status

// Check checks the status of each status, return the first that does not pass.
func (s ManyStatus) Check() *Status {
	for _, status := range s {
		if s == nil {
			continue
		}
		if !status.Healthy {
			return status
		}
	}
	status := &Status{
		Healthy:   true,
		Status:    StatusOKWalletIssue,
		Timestamp: time.Now(),
	}
	return status
}

// MonitoringCertClients contains status for client certificates
type MonitoringCertClients map[string]*MonitoringCertClient

// MonitoringCertClient contains status for client certificates
type MonitoringCertClient struct {
	Valid       bool      `json:"valid,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	DaysLeft    int       `json:"days_left,omitempty"`
	LastChecked time.Time `json:"last_checked,omitempty"`
}
