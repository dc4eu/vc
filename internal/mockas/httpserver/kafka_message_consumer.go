package httpserver

import (
	"context"
	"encoding/json"
	"github.com/IBM/sarama"
	"vc/internal/mockas/apiv1"
	"vc/pkg/logger"
	"vc/pkg/trace"
)

type MockNextHandler struct {
	Log    *logger.Log
	ApiV1  *apiv1.Client
	Tracer *trace.Tracer
}

func (h *MockNextHandler) HandleMessage(ctx context.Context, message *sarama.ConsumerMessage) error {
	var mockNextRequest apiv1.MockNextRequest
	if err := json.Unmarshal(message.Value, &mockNextRequest); err != nil {
		h.Log.Error(err, "Failed to unmarshal event from Kafka")
		return err
	}

	_, err := h.ApiV1.MockNext(ctx, &mockNextRequest)
	if err != nil {
		h.Log.Error(err, "Failed to handle MockNextRequest")
		return err
	}
	return nil
}
