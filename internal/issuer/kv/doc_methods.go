package kv

import (
	"context"
	"fmt"
	"time"
)

// Doc holds the document kv object
type Doc struct {
	client *Service
	key    string
}

// SaveLadokUID saves the ladok uid for the transaction
func (d *Doc) SaveLadokUID(ctx context.Context, transactionID, ladokUID string) error {
	key := fmt.Sprintf(d.key, transactionID, "ladok")
	return d.client.redisClient.HSet(ctx, key, "uid", ladokUID).Err()
}

// GetLadokUID gets the ladok uid for the transaction
func (d *Doc) GetLadokUID(ctx context.Context, transactionID string) (string, error) {
	key := fmt.Sprintf(d.key, transactionID, "ladok")
	return d.client.redisClient.HGet(ctx, key, "uid").Result()
}

// SaveUnsigned saves the unsigned document and the timestamp when it was created
func (d *Doc) SaveUnsigned(ctx context.Context, transactionID, data string, ts int64) error {
	key := fmt.Sprintf(d.key, transactionID, "unsigned")

	if err := d.client.redisClient.HSet(ctx, key, "data", data).Err(); err != nil {
		return err
	}
	if err := d.client.redisClient.HSet(ctx, key, "ts", ts).Err(); err != nil {
		return err
	}
	return nil
}

// GetUnsigned gets the unsigned document and the timestamp when it was created
func (d *Doc) GetUnsigned(ctx context.Context, transactionID string) (string, int64, error) {
	key := fmt.Sprintf(d.key, transactionID, "unsigned")

	data, err := d.client.redisClient.HGet(ctx, key, "data").Result()
	if err != nil {
		return "", 0, err
	}
	ts, err := d.client.redisClient.HGet(ctx, key, "ts").Int64()
	if err != nil {
		return "", 0, err
	}

	return data, ts, nil
}

// DelUnsigned deletes the unsigned document
func (d *Doc) DelUnsigned(ctx context.Context, transactionID string) error {
	key := fmt.Sprintf(d.key, transactionID, "unsigned")
	return d.client.redisClient.HDel(ctx, key, "data", "ts").Err()
}

// AddTTLUnsigned marks the unsigned document for deletion
func (d *Doc) AddTTLUnsigned(ctx context.Context, transactionID string) error {
	key := fmt.Sprintf(d.key, transactionID, "unsigned")
	return d.client.redisClient.Expire(ctx, key, 1*time.Hour).Err()
}

// SaveSigned saves the signed document and the timestamp when it was signed
func (d *Doc) SaveSigned(ctx context.Context, transactionID, data string, ts int64) error {
	key := fmt.Sprintf(d.key, transactionID, "signed")

	if err := d.client.redisClient.HSet(ctx, key, "data", data).Err(); err != nil {
		return err
	}
	if err := d.client.redisClient.HSet(ctx, key, "ts", ts).Err(); err != nil {
		return err
	}

	return nil
}

// GetSigned returns the signed document and the timestamp when it was signed
func (d *Doc) GetSigned(ctx context.Context, transactionID string) (string, int64, error) {
	key := fmt.Sprintf(d.key, transactionID, "signed")

	data, err := d.client.redisClient.HGet(ctx, key, "data").Result()
	if err != nil {
		return "", 0, err
	}
	ts, err := d.client.redisClient.HGet(ctx, key, "ts").Int64()
	if err != nil {
		return "", 0, err
	}

	return data, ts, nil
}

// DelSigned deletes the signed document
func (d *Doc) DelSigned(ctx context.Context, transactionID string) error {
	key := fmt.Sprintf(d.key, transactionID, "signed")
	return d.client.redisClient.HDel(ctx, key, "data", "ts").Err()
}

// SaveRevoked saves the timestamp when the document was revoked
func (d *Doc) SaveRevoked(ctx context.Context, transactionID string, revokedTS int64) error {
	key := fmt.Sprintf(d.key, transactionID, "revoked")
	if err := d.client.redisClient.HSet(ctx, key, "ts", revokedTS).Err(); err != nil {
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
