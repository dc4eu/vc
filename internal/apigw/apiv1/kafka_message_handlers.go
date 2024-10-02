package apiv1

import (
	"context"
	"encoding/json"
	"github.com/IBM/sarama"
	"vc/pkg/logger"
	"vc/pkg/trace"
)

type UploadMessageHandler struct {
	log    *logger.Log
	apiv1  *Client
	tracer *trace.Tracer
}

func NewUploadMessageHandler(log *logger.Log, apiv1 *Client, tracer *trace.Tracer) *UploadMessageHandler {
	return &UploadMessageHandler{
		log:    log,
		apiv1:  apiv1,
		tracer: tracer,
	}
}

func (h *UploadMessageHandler) HandleMessage(ctx context.Context, message *sarama.ConsumerMessage) error {
	var uploadRequest UploadRequest
	if err := json.Unmarshal(message.Value, &uploadRequest); err != nil {
		h.log.Error(err, "Failed to unmarshal message.Value from Kafka")
		return err
	}

	err := h.apiv1.Upload(ctx, &uploadRequest)
	if err != nil {
		h.log.Error(err, "Failed to handle UploadRequest")
		return err
	}
	return nil
}
