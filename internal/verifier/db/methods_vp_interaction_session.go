package db

import (
	"context"
	"errors"
	"vc/pkg/openid4vp"
	"vc/pkg/openid4vp/db"
)

// VPInteractionSessionColl is the generic collection for a openid4vp session against the verifier
type VPInteractionSessionColl struct {
	repo *db.InMemoryRepo[openid4vp.VPInteractionSession]

	//log *logger.Log
}

func (c *VPInteractionSessionColl) Create(ctx context.Context, vpSession *openid4vp.VPInteractionSession) error {
	_, err := c.repo.Create(&db.Entry[openid4vp.VPInteractionSession]{
		ID:   vpSession.SessionID,
		Data: vpSession,
	})
	if err != nil {
		return err
	}
	return nil
}

func (c *VPInteractionSessionColl) Read(ctx context.Context, sessionID string) (*openid4vp.VPInteractionSession, error) {
	vpSessionEntry, found := c.repo.Read(sessionID)
	if !found {
		return nil, errors.New("session not found")
	}
	return vpSessionEntry.Data, nil
}
