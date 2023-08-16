package model

import (
	"fmt"
	"log"
	"time"
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
type Probes []*Probe

// Check checks the status of each status, return the first that does not pass.
func (probes Probes) Check(serviceName string) *Health {
	health := &Health{
		ServiceName: serviceName,
		Probes:      []*Probe{},
		Status:      fmt.Sprintf(StatusOK, serviceName),
	}

	if probes == nil {
		log.Println("probe is nil")
		return health
	}

	for _, probe := range probes {
		if !probe.Healthy {
			health.Status = fmt.Sprintf(StatusFail, serviceName)
		}
		health.Probes = append(health.Probes, probe)
	}

	return health
}
