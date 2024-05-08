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

type LoginReply struct {
	SessionKey string `json:"session_key"`
	Username   string `json:"username"`
}

func (c *Client) Login(ctx context.Context, req *LoginRequest) (*LoginReply, error) {

	c.log.Info("From browser", req.Username, req.Password)

	if req.Username != c.cfg.UI.Username || req.Password != c.cfg.UI.Password {
		return nil, errors.New("invalid username or password")
	}

	uuid := uuid.NewString()

	reply := &LoginReply{
		SessionKey: uuid,
		Username:   c.cfg.UI.Username,
	}

	return reply, nil
}
