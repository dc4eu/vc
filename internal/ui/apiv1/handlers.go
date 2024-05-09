package apiv1

import (
	"context"
	"errors"
	"time"
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
	//SessionKey string `json:"session_key" binding:"required"`
	Username     string    `json:"username" binding:"required"`
	LoggedInTime time.Time `json:"logged_in_time" binding:"required"` //time.Time encoded to JSON will use the RFC3339 format by default, which is essentially ISO 8601 (e.g., "2024-05-09T14:00:00Z"
}

func (c *Client) Login(ctx context.Context, req *LoginRequest) (*LoggedinReply, error) {

	//c.log.Info("From browser username and password", req.Username, req.Password)

	if req.Username != c.cfg.UI.Username || req.Password != c.cfg.UI.Password {
		return nil, errors.New("Invalid username and/or password")
	}

	//uuid := uuid.NewString()

	reply := &LoggedinReply{
		//SessionKey: uuid,
		Username:     c.cfg.UI.Username,
		LoggedInTime: time.Now(),
	}

	return reply, nil
}

func (c *Client) Logout(ctx context.Context) error {
	return nil
}
