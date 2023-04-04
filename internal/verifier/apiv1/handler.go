package apiv1

import (
	"context"
	"wallet/pkg/model"
)

// Status return status for each ladok instance
func (c *Client) Status(ctx context.Context) (*model.Status, error) {
	manyStatus := model.ManyStatus{}

	//for _, ladok := range c.ladokInstances {
	//	redis := ladok.Atom.StatusRedis(ctx)
	//	ladok := ladok.Rest.StatusLadok(ctx)

	//	manyStatus = append(manyStatus, redis)
	//	manyStatus = append(manyStatus, ladok)
	//}
	status := manyStatus.Check()

	return status, nil
}

// MonitoringCertClient return status for client certificates
func (c *Client) MonitoringCertClient(ctx context.Context) (*model.MonitoringCertClients, error) {
	//clientCertificates := model.MonitoringCertClients{}
	//for schoolName, ladok := range c.ladokInstances {
	//	clientCertificates[schoolName] = ladok.Certificate.ClientCertificateStatus
	//}
	return nil, nil
}
