package apiv1

import (
	"context"
	"fmt"
	"vc/pkg/openid4vp"
)

type PaginatedVerificationRecordsRequest struct {
	RequestedSequenceStart int64 `json:"requested_sequence_start" validate:"required,gt=0"`
	RequestedSequenceEnd   int64 `json:"requested_sequence_end" validate:"required,gt=0"`
}

type VerificationRecord struct {
	Sequence         int64                       `json:"sequence" bson:"sequence" validate:"required"`
	ID               string                      `json:"id" bson:"session_id" validate:"required"` //Same as session_id but not exposed as that externally
	VerificationMeta *openid4vp.VerificationMeta `json:"verification_meta" bson:"verification_meta" validate:"required"`
	VPResults        []*VPResult                 `json:"vp_results" bson:"vp_results"`
}

type VPResult struct {
	VCResults []*VCResult `json:"vc_results" bson:"vc_results"`
}

type VCResult struct {
	ValidSelectiveDisclosures []*openid4vp.Disclosure `json:"valid_selective_disclosures" bson:"valid_selective_disclosures"`
	Claims                    map[string]interface{}  `json:"claims" bson:"claims"`
}

type PaginatedVerificationRecordsReply struct {
	RequestedSequenceStart int64                 `json:"requested_sequence_start" validate:"required"`
	RequestedSequenceEnd   int64                 `json:"requested_sequence_end" validate:"required"`
	SequenceMax            int64                 `json:"sequence_max" validate:"required"`
	Items                  []*VerificationRecord `json:"verification_records"`
}

func (c *Client) PaginatedVerificationRecords(ctx context.Context, request *PaginatedVerificationRecordsRequest) (*PaginatedVerificationRecordsReply, error) {
	if request.RequestedSequenceEnd < request.RequestedSequenceStart {
		return nil, fmt.Errorf(
			"requested_sequence_end (%d) must be greater than or equal to requested_sequence_start (%d)",
			request.RequestedSequenceEnd,
			request.RequestedSequenceStart,
		)
	}
	//TODO: Ta in max antal tillåtna items per "reply" via config, satt till 3 för att underlätta utveckingsarbetet
	maxAllowedItems := int64(3)
	requestedNumOfItems := (request.RequestedSequenceEnd - request.RequestedSequenceStart) + 1
	if requestedNumOfItems > maxAllowedItems {
		return nil, fmt.Errorf("max allowed sequence range is (%d), requested was (%d)", maxAllowedItems, requestedNumOfItems)
	}

	//TODO: refactor below when MongoDB is being used
	dbRecords, err := c.db.VerificationRecordColl.ReadAll(ctx)
	if err != nil {
		return nil, err
	}

	records := make([]*VerificationRecord, 0, requestedNumOfItems)
	sequenceMax := int64(0)
	for _, dbRecord := range dbRecords {
		if dbRecord == nil {
			continue
		}
		if sequenceMax < dbRecord.Sequence {
			sequenceMax = dbRecord.Sequence
		}

		if isInRange(dbRecord.Sequence, request.RequestedSequenceStart, request.RequestedSequenceEnd) {
			records = append(records, c.buildVerificationRecordFrom(dbRecord))
		}
	}

	reply := &PaginatedVerificationRecordsReply{
		RequestedSequenceStart: request.RequestedSequenceStart,
		RequestedSequenceEnd:   request.RequestedSequenceEnd,
		SequenceMax:            sequenceMax,
		Items:                  records,
	}

	return reply, nil
}

func (c *Client) buildVerificationRecordFrom(dbRecord *openid4vp.VerificationRecord) *VerificationRecord {
	//Will be handled by mongo later
	var vpResults []*VPResult
	for _, vp := range dbRecord.VPResults {
		var vcResults []*VCResult
		for _, vc := range vp.VCResults {
			vcResult := &VCResult{
				ValidSelectiveDisclosures: vc.ValidSelectiveDisclosures,
				Claims:                    vc.Claims,
			}
			vcResults = append(vcResults, vcResult)
		}
		vpResult := &VPResult{
			VCResults: vcResults,
		}
		vpResults = append(vpResults, vpResult)
	}

	return &VerificationRecord{
		Sequence:         dbRecord.Sequence,
		ID:               dbRecord.SessionID,
		VerificationMeta: dbRecord.VerificationMeta,
		VPResults:        vpResults,
	}
}

func isInRange(seq, start, end int64) bool {
	return seq >= start && seq <= end
}
