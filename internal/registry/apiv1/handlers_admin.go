package apiv1

import (
	"context"
	"fmt"
)

// SearchPersonRequest is the request for searching credential subjects by person info
type SearchPersonRequest struct {
	FirstName   string `form:"first_name"`
	LastName    string `form:"last_name"`
	DateOfBirth string `form:"date_of_birth"`
}

// PersonResult represents a person with their TSL info and current status
type PersonResult struct {
	FirstName   string
	LastName    string
	DateOfBirth string
	Section     int64
	Index       int64
	Status      uint8
}

// SearchPersonReply is the reply for searching credential subjects
type SearchPersonReply struct {
	Results []*PersonResult
}

// SearchPerson searches for credential subjects by name and/or date of birth
func (c *Client) SearchPerson(ctx context.Context, req *SearchPersonRequest) (*SearchPersonReply, error) {
	if c.credentialSubjects == nil {
		return nil, fmt.Errorf("credential subjects database not configured")
	}

	docs, err := c.credentialSubjects.Search(ctx, req.FirstName, req.LastName, req.DateOfBirth)
	if err != nil {
		c.log.Error(err, "Failed to search credential subjects")
		return nil, err
	}

	results := make([]*PersonResult, 0, len(docs))
	for _, doc := range docs {
		result := &PersonResult{
			FirstName:   doc.FirstName,
			LastName:    doc.LastName,
			DateOfBirth: doc.DateOfBirth,
			Section:     doc.Section,
			Index:       doc.Index,
		}

		// Fetch current status from TSL
		if c.adminDB != nil {
			tslDoc, err := c.adminDB.FindOne(ctx, doc.Section, doc.Index)
			if err == nil && tslDoc != nil {
				result.Status = tslDoc.Status
			}
		}

		results = append(results, result)
	}

	return &SearchPersonReply{Results: results}, nil
}

// UpdateStatusRequest is the request for updating a person's credential status
type UpdateStatusRequest struct {
	Section int64 `form:"section" validate:"gte=0"`
	Index   int64 `form:"index" validate:"gte=0"`
	Status  uint8 `form:"status" validate:"gte=0,lte=255"`
	// Search parameters to preserve after update
	SearchFirstName   string `form:"search_first_name"`
	SearchLastName    string `form:"search_last_name"`
	SearchDateOfBirth string `form:"search_date_of_birth"`
}

// UpdateStatus updates the status of a credential in the TSL
func (c *Client) UpdateStatus(ctx context.Context, req *UpdateStatusRequest) error {
	if c.adminDB == nil {
		return fmt.Errorf("database not configured")
	}

	if err := c.adminDB.UpdateStatus(ctx, req.Section, req.Index, req.Status); err != nil {
		c.log.Error(err, "Failed to update status", "section", req.Section, "index", req.Index, "status", req.Status)
		return err
	}

	// Invalidate the TSL cache for this section so changes are reflected
	if c.tslIssuer != nil {
		if invalidator, ok := c.tslIssuer.(interface{ InvalidateSection(int64) }); ok {
			invalidator.InvalidateSection(req.Section)
		}
	}

	c.log.Info("Status updated", "section", req.Section, "index", req.Index, "status", req.Status)
	return nil
}
