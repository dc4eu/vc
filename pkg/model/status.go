package model

import (
	"fmt"
	"log"
	"time"
	apiv1_status "vc/internal/gen/status/apiv1.status"
)

var (
	//StatusOK status ok
	StatusOK = "STATUS_OK_%s"
	// StatusFail status fail
	StatusFail = "STATUS_FAIL_%s"
)

// Health contains status for each service
type Health struct {
	ServiceName string   `json:"service_name,omitempty"`
	Probes      []*Probe `json:"probes,omitempty"`
	Status      string   `json:"status,omitempty"`
}

// Probe type
type Probe struct {
	Name          string    `json:"name,omitempty"`
	Healthy       bool      `json:"healthy,omitempty"`
	Message       string    `json:"message,omitempty"`
	LastCheckedTS time.Time `json:"timestamp,omitempty"`
}

// ProbeStore contains the previous probe result and the next time to check
type ProbeStore struct {
	NextCheck      time.Time
	PreviousResult *Probe
}

// Probes contains probes
type Probes []*apiv1_status.StatusProbe

// Check checks the status of each status, return the first that does not pass.
func (probes Probes) Check(serviceName string) *apiv1_status.StatusReply {
	health := &apiv1_status.StatusReply{
		Data: &apiv1_status.StatusReply_Data{
			ServiceName: serviceName,
			Probes:      []*apiv1_status.StatusProbe{},
			Status:      fmt.Sprintf(StatusOK, serviceName),
		},
	}

	if probes == nil {
		log.Println("probe is nil")
		return health
	}

	for _, probe := range probes {
		if !probe.Healthy {
			health.Data.Status = fmt.Sprintf(StatusFail, serviceName)
		}
		health.Data.Probes = append(health.Data.Probes, probe)
	}

	return health
}
