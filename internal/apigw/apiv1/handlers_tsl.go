package apiv1

import (
	"context"
	"strconv"

	"vc/internal/gen/registry/apiv1_registry"
	"vc/pkg/tsl"
)

// StatusListsAddRecordRequest represents the request for adding a record to the status list.
// This is an internal API for the issuer to allocate indices for new credentials.
type StatusListsAddRecordRequest struct {
	// Status is the initial status value for the record (0=VALID, 1=INVALID, 2=SUSPENDED)
	// Defaults to 0 (VALID) if not specified
	Status *uint8 `json:"status"`
}

// StatusListsAddRecordResponse represents the response after adding a record to the status list.
type StatusListsAddRecordResponse struct {
	// Section is the section ID where the record was added
	Section int64 `json:"section"`

	// Index is the index within the section for this record
	Index int64 `json:"index"`

	// URI is the full Status List Token URI for the status claim in a Referenced Token
	URI string `json:"uri"`
}

// StatusListsAddRecord handles requests to add a new record to the status list.
// This is an internal API used by the issuer when issuing new credentials.
// It allocates a new index in the current section and returns the section/index pair
// that should be embedded in the Referenced Token's status claim.
//
// Request Body (JSON):
//   - status: Optional. Initial status value (0=VALID, 1=INVALID, 2=SUSPENDED). Defaults to 0.
//
// Response (JSON):
//   - section: The section ID where the record was added
//   - index: The index within the section for this record
//   - uri: The full Status List Token URI for the status claim
func (c *Client) StatusListsAddRecord(ctx context.Context, req *StatusListsAddRecordRequest) (*StatusListsAddRecordResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:StatusListsAddRecord")
	defer span.End()

	c.log.Debug("status_lists_add_record", "request", req)

	// Default to VALID status if not specified
	status := uint32(0) // tsl.StatusValid
	if req.Status != nil {
		status = uint32(*req.Status)
	}

	// Validate status value (0-2 are the standard values per Section 7.1)
	if status > 2 {
		c.log.Error(nil, "invalid status value", "status", status)
		return nil, tsl.ErrInvalidStatusValue
	}

	// Call registry via gRPC to add the status
	grpcReq := &apiv1_registry.TSLAddStatusRequest{
		Status: status,
	}
	grpcReply, err := c.registryClient.TSLAddStatus(ctx, grpcReq)
	if err != nil {
		c.log.Error(err, "failed to add status record via registry gRPC")
		return nil, err
	}

	// Build the Status List Token URI (pointing to registry)
	uri := c.cfg.Registry.ExternalServerURL + "/statuslists/" + strconv.FormatInt(grpcReply.Section, 10)

	reply := &StatusListsAddRecordResponse{
		Section: grpcReply.Section,
		Index:   grpcReply.Index,
		URI:     uri,
	}

	c.log.Debug("status_lists_add_record", "reply", reply)

	return reply, nil
}
