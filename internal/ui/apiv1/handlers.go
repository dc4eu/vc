package apiv1

import (
	"context"
	"errors"
	"time"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/internal/ui/representations"
	"vc/pkg/model"
)

// Status return status for the service
func (c *Client) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	probes := model.Probes{}

	status := probes.Check("ui")

	return status, nil
}

func (c *Client) Login(ctx context.Context, req *representations.LoginRequest) (*representations.LoggedinReply, error) {

	//c.log.Info("From browser username and password", req.Username, req.Password)

	if req.Username != c.cfg.UI.Username || req.Password != c.cfg.UI.Password {
		return nil, errors.New("Invalid username and/or password")
	}

	//uuid := uuid.NewString()

	reply := &representations.LoggedinReply{
		//SessionKey: uuid,
		Username:     c.cfg.UI.Username,
		LoggedInTime: time.Now(),
	}

	return reply, nil
}

func (c *Client) Logout(ctx context.Context) error {
	return nil
}

func (c *Client) User(ctx context.Context) (*representations.LoggedinReply, error) {
	return nil, nil
}

func (c *Client) Portal(ctx context.Context, req *representations.PortalRequest) (*any, error) {
	reply, err := c.apigwc.Portal(req)
	if err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *Client) MockNext(ctx context.Context, req *representations.PortalRequest) (*any, error) {
	reply, err := c.mockasc.MockNext(req)
	if err != nil {
		return nil, err
	}
	return &reply, nil
}
