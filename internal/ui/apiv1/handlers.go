package apiv1

import (
	"context"
	"errors"
	"time"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/pkg/model"
)

func (c *Client) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	probes := model.Probes{}
	status := probes.Check("ui")
	return status, nil
}

func (c *Client) Login(ctx context.Context, req *LoginRequest) (*LoggedinReply, error) {
	//c.log.Info("From browser username and password", req.Username, req.Password)

	if req.Username != c.cfg.UI.Username || req.Password != c.cfg.UI.Password {
		return nil, errors.New("invalid username and/or password")
	}

	reply := &LoggedinReply{
		Username:     c.cfg.UI.Username,
		LoggedInTime: time.Now(),
	}

	return reply, nil
}

func (c *Client) Logout(ctx context.Context) error {
	return nil
}

func (c *Client) User(ctx context.Context) (*LoggedinReply, error) {
	return nil, nil
}

func (c *Client) Portal(ctx context.Context, req *PortalRequest) (*any, error) {
	reply, err := c.apigwc.Portal(req)
	if err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *Client) MockNext(ctx context.Context, req *MockNextRequest) (*any, error) {
	reply, err := c.mockasc.MockNext(req)
	if err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *Client) StatusAPIGW(ctx context.Context, req *apiv1_status.StatusRequest) (*any, error) {
	reply, err := c.apigwc.Status()
	if err != nil {
		return nil, err
	}
	return &reply, nil
}
