package db

import (
	"context"
	"errors"
	"vc/pkg/openid4vp"
	"vc/pkg/openid4vp/db"
)

// VerificationRecord is the generic collection of the verification of verifiable presentations (i.e., credentials, claims, etc) received in an authorization response from a holder (wallet).
type VerificationRecordColl struct {
	repo *db.InMemoryRepo[openid4vp.VerificationRecord]

	//log *logger.Log
}

func (c *VerificationRecordColl) Create(ctx context.Context, verificationRecord *openid4vp.VerificationRecord) error {
	_, err := c.repo.Create(&db.Entry[openid4vp.VerificationRecord]{
		ID:   verificationRecord.SessionID,
		Data: verificationRecord,
	})
	if err != nil {
		return err
	}
	return nil
}

func (c *VerificationRecordColl) Read(ctx context.Context, sessionID string) (*openid4vp.VerificationRecord, error) {
	verificationRecordEntry := c.repo.Read(sessionID)
	if verificationRecordEntry == nil || verificationRecordEntry.Data == nil {
		return nil, errors.New("VerificationRecord not found")
	}
	return verificationRecordEntry.Data, nil
}

// TODO: only for dev purpose - valid vp's datastore needs a better api against the consuming system (ex. hämta de älsta och max 100, sedan hämta de 100 nyare än den osv via auto-increment nummer eller liknande - påminner om en ATOM-feed hämtning såvida inte någon queue/topics används)???)
func (c *VerificationRecordColl) ReadAll(ctx context.Context) ([]*openid4vp.VerificationRecord, error) {
	allVerificationRecordEntrys := c.repo.ReadAll()
	allVerificationRecord := make([]*openid4vp.VerificationRecord, len(allVerificationRecordEntrys))
	for i, entry := range allVerificationRecordEntrys {
		allVerificationRecord[i] = entry.Data
	}
	return allVerificationRecord, nil

}

func (c *VerificationRecordColl) Delete(ctx context.Context, sessionID string) error {
	c.repo.Delete(sessionID)
	return nil
}

func (c *VerificationRecordColl) Update(ctx context.Context, verificationRecord *openid4vp.VerificationRecord) error {
	//Nothing to do since it's an in memory db
	return nil
}
