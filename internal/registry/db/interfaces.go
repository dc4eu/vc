package db

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// StatusListStore defines the interface for status list operations
type StatusListStore interface {
	CountDocs(ctx context.Context, filter bson.M) (int64, error)
	CreateNewSection(ctx context.Context, section int64, sectionSize int64) error
	Add(ctx context.Context, section int64, status uint8) (int64, error)
	UpdateStatus(ctx context.Context, section int64, index int64, status uint8) error
	GetAllStatusesForSection(ctx context.Context, section int64) ([]uint8, error)
	InitializeIfEmpty(ctx context.Context) error
	FindOne(ctx context.Context, section, index int64) (*TSLDoc, error)
}

// StatusListMetadataStore defines the interface for status list metadata operations
type StatusListMetadataStore interface {
	GetCurrentSection(ctx context.Context) (int64, error)
	UpdateCurrentSection(ctx context.Context, newSection int64) error
	GetAllSections(ctx context.Context) ([]int64, error)
}

// Ensure concrete types implement the interfaces
var _ StatusListStore = (*TSLColl)(nil)
var _ StatusListMetadataStore = (*TSLMetadataColl)(nil)
