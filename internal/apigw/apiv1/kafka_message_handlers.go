package apiv1

import (
	"context"
	"encoding/json"
	"github.com/IBM/sarama"
	"vc/pkg/logger"
	"vc/pkg/trace"
)

type UploadMessageHandler struct {
	Log    *logger.Log
	ApiV1  *Client
	Tracer *trace.Tracer
}

func (h *UploadMessageHandler) HandleMessage(ctx context.Context, message *sarama.ConsumerMessage) error {
	var uploadRequest UploadRequest
	if err := json.Unmarshal(message.Value, &uploadRequest); err != nil {
		h.Log.Error(err, "Failed to unmarshal message.Value from Kafka")
		return err
	}

	err := h.ApiV1.Upload(ctx, &uploadRequest)
	if err != nil {
		h.Log.Error(err, "Failed to handle UploadRequest")
		return err
	}
	return nil
}
