package db

import (
	"context"
	"errors"
	"vc/pkg/openid4vp"
	"vc/pkg/openid4vp/db"
)

// VPInteractionSessionColl is the generic collection for all openid4vp sessions against the verifier
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
	vpSessionEntry := c.repo.Read(sessionID)
	if vpSessionEntry == nil || vpSessionEntry.Data == nil {
		return nil, errors.New("VPInteractionSession not found")
	}
	return vpSessionEntry.Data, nil
}

func (c *VPInteractionSessionColl) Delete(ctx context.Context, sessionID string) error {
	c.repo.Delete(sessionID)
	return nil
}

func (c *VPInteractionSessionColl) Update(ctx context.Context, vpSession *openid4vp.VPInteractionSession) error {
	//Nothing to do since it's an in memory db
	return nil
}
