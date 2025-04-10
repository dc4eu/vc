package apiv1

import (
	"context"
	"fmt"
)

type PaginatedVerificationRecordsRequest struct {
	RequestedSequenceStart int64 `json:"requested_sequence_start" validate:"required,gt=0"`
	RequestedSequenceEnd   int64 `json:"requested_sequence_end" validate:"required,gt=0"`
}

type VerificationRecordReply struct {
	Sequence int64  `json:"sequence" bson:"sequence" validate:"required"`
	ID       string `json:"id" bson:"session_id" validate:"required"` //Same as session_id but not exposed as that externally
	//CallbackID             string                  `json:"callback_id" bson:"callback_id" validate:"required"`
	//TODO: t b c with the vp's and vc's
}

type PaginatedVerificationRecordsReply struct {
	RequestedSequenceStart int64 `json:"requested_sequence_start" validate:"required"`
	RequestedSequenceEnd   int64 `json:"requested_sequence_end" validate:"required"`
	//HighestFetchedSequence int64                      `json:"highest_fetched_sequence"`
	SequenceMax int64                      `json:"sequence_max" validate:"required"`
	Items       []*VerificationRecordReply `json:"verification_records"`
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

	items := make([]*VerificationRecordReply, 0, requestedNumOfItems)
	sequenceMax := int64(0)
	for _, dbRecord := range dbRecords {
		if dbRecord == nil {
			continue
		}
		if sequenceMax < dbRecord.Sequence {
			sequenceMax = dbRecord.Sequence
		}
		if isInRange(dbRecord.Sequence, request.RequestedSequenceStart, request.RequestedSequenceEnd) {
			items = append(items, &VerificationRecordReply{
				Sequence: dbRecord.Sequence,
				ID:       dbRecord.SessionID,
				//TODO t b c
			})
		}
	}

	reply := &PaginatedVerificationRecordsReply{
		RequestedSequenceStart: request.RequestedSequenceStart,
		RequestedSequenceEnd:   request.RequestedSequenceEnd,
		SequenceMax:            sequenceMax,
		Items:                  items,
	}

	return reply, nil
}

func isInRange(seq, start, end int64) bool {
	return seq >= start && seq <= end
}
