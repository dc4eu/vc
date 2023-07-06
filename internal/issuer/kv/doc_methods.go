package kv

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/masv3971/gosunetca/types"
)

// Doc holds the document kv object
type Doc struct {
	client *Service
	key    string
}

// SaveUnsigned saves the unsigned document and the timestamp when it was created
func (d *Doc) SaveUnsigned(ctx context.Context, doc *types.Document) error {
	d.client.log.Debug("SaveUnsigned", "transaction_id", doc.TransactionID)
	key := fmt.Sprintf(d.key, doc.TransactionID, "unsigned")
	if err := d.client.redisClient.HSet(ctx, key, doc).Err(); err != nil {
		d.client.log.Debug("SaveUnsigned", "error", err)
		return err
	}
	return nil
}

// GetUnsigned gets the unsigned document and the timestamp when it was created
func (d *Doc) GetUnsigned(ctx context.Context, transactionID string) (*types.Document, error) {
	if d.IsRevoked(ctx, transactionID) {
		return nil, fmt.Errorf("document is revoked")
	}

	key := fmt.Sprintf(d.key, transactionID, "unsigned")
	dest := &types.Document{}
	if err := d.client.redisClient.HGetAll(ctx, key).Scan(dest); err != nil {
		return nil, err
	}
	return dest, nil
}

// DelUnsigned deletes the unsigned document
func (d *Doc) DelUnsigned(ctx context.Context, transactionID string) error {
	key := fmt.Sprintf(d.key, transactionID, "unsigned")
	return d.client.redisClient.HDel(ctx, key, "data", "ts").Err()
}

// AddTTLUnsigned marks the unsigned document for deletion
func (d *Doc) AddTTLUnsigned(ctx context.Context, transactionID string) error {
	// Add modifyTS to the document
	key := fmt.Sprintf(d.key, transactionID, "unsigned")
	expTime := time.Duration(d.client.cfg.Issuer.KeyValue.PDF.KeepUnsignedDuration)
	return d.client.redisClient.Expire(ctx, key, expTime*time.Second).Err()
}

// SaveSigned saves the signed document and the timestamp when it was signed
func (d *Doc) SaveSigned(ctx context.Context, doc *types.Document) error {
	// Add modifyTS to the document
	if doc.Data == "" {
		return errors.New("Data is empty")
	}
	key := fmt.Sprintf(d.key, doc.TransactionID, "signed")
	d.client.log.Debug("SaveSigned", "key", key)
	if err := d.client.redisClient.HSet(ctx, key, doc).Err(); err != nil {
		return err
	}
	return nil
}

// GetSigned returns the signed document and the timestamp when it was signed
func (d *Doc) GetSigned(ctx context.Context, transactionID string) (*types.Document, error) {
	if d.IsRevoked(ctx, transactionID) {
		return nil, fmt.Errorf("document is revoked")
	}

	key := fmt.Sprintf(d.key, transactionID, "signed")
	dest := &types.Document{}
	if err := d.client.redisClient.HGetAll(ctx, key).Scan(dest); err != nil {
		return nil, err
	}
	return dest, nil
}

// ExistsSigned returns true if the signed document exists
func (d *Doc) ExistsSigned(ctx context.Context, transactionID string) bool {
	key := fmt.Sprintf(d.key, transactionID, "signed")
	return d.client.redisClient.Exists(ctx, key).Val() == 1
}

// DelSigned deletes the signed document
func (d *Doc) DelSigned(ctx context.Context, transactionID string) error {
	key := fmt.Sprintf(d.key, transactionID, "signed")
	return d.client.redisClient.HDel(ctx, key, "data", "ts").Err()
}

// AddTTLSigned marks the signed document for deletion
func (d *Doc) AddTTLSigned(ctx context.Context, transactionID string) error {
	key := fmt.Sprintf(d.key, transactionID, "signed")
	expTime := time.Duration(d.client.cfg.Issuer.KeyValue.PDF.KeepSignedDuration)
	return d.client.redisClient.Expire(ctx, key, expTime*time.Second).Err()
}

// SaveRevoked saves the timestamp when the document was revoked
func (d *Doc) SaveRevoked(ctx context.Context, transactionID string) error {
	key := fmt.Sprintf(d.key, transactionID, "revoked")
	if err := d.client.redisClient.HSet(ctx, key, "ts", time.Now().Unix()).Err(); err != nil {
		return err
	}
	return nil
}

// GetRevoked returns the timestamp when the document was revoked
func (d *Doc) GetRevoked(ctx context.Context, transactionID string) (int64, error) {
	key := fmt.Sprintf(d.key, transactionID, "revoked")
	return d.client.redisClient.HGet(ctx, key, "ts").Int64()
}

// IsRevoked returns true if the document is revoked
func (d *Doc) IsRevoked(ctx context.Context, transactionID string) bool {
	key := fmt.Sprintf(d.key, transactionID, "revoked")
	return d.client.redisClient.HExists(ctx, key, "ts").Val()
}
