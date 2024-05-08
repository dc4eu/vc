package apiv1

import (
	"context"
	"errors"
	"github.com/google/uuid"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/pkg/model"
)

// Status return status for the service
func (c *Client) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	probes := model.Probes{}

	status := probes.Check("ui")

	return status, nil
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoggedinReply struct {
	SessionKey string `json:"session_key" binding:"required"`
	Username   string `json:"username" binding:"required"`
}

func (c *Client) Login(ctx context.Context, req *LoginRequest) (*LoggedinReply, error) {

	//TODO: ta bort nedan logging av username och password
	c.log.Info("From browser username and password", req.Username, req.Password)

	if req.Username != c.cfg.UI.Username || req.Password != c.cfg.UI.Password {
		return nil, errors.New("Invalid username and/or password")
	}

	uuid := uuid.NewString()

	reply := &LoggedinReply{
		SessionKey: uuid,
		Username:   c.cfg.UI.Username,
	}

	return reply, nil
}
