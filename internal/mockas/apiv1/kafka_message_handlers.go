package apiv1

import (
	"context"
	"encoding/json"
	"github.com/IBM/sarama"
	"vc/pkg/logger"
	"vc/pkg/trace"
)

type MockNextMessageHandler struct {
	Log    *logger.Log
	ApiV1  *Client
	Tracer *trace.Tracer
}

func (h *MockNextMessageHandler) HandleMessage(ctx context.Context, message *sarama.ConsumerMessage) error {
	var mockNextRequest MockNextRequest
	if err := json.Unmarshal(message.Value, &mockNextRequest); err != nil {
		h.Log.Error(err, "Failed to unmarshal message.Value from Kafka")
		return err
	}

	_, err := h.ApiV1.MockNext(ctx, &mockNextRequest)
	if err != nil {
		h.Log.Error(err, "Failed to handle MockNextRequest")
		return err
	}
	return nil
}

type UploadMessageHandler struct {
	Log    *logger.Log
	ApiV1  *Client
	Tracer *trace.Tracer
}

// TODO: REMOVE ME, JUST TO TEST A SECOND KAFKA CONSUMER GROUP FROM A DIFFERENT SERVICE
func (h *UploadMessageHandler) HandleMessage(ctx context.Context, message *sarama.ConsumerMessage) error {
	h.Log.Debug("Consuming message just to log it to debug", "message.Key", string(message.Key), "message.Topic", message.Topic, "message.Value", string(message.Value))
	return nil
}
