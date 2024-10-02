package apiv1

import (
	"context"
	"encoding/json"
	"github.com/IBM/sarama"
	"vc/pkg/logger"
	"vc/pkg/trace"
)

type MockNextMessageHandler struct {
	log    *logger.Log
	apiv1  *Client
	tracer *trace.Tracer
}

func NewMockNextMessageHandler(log *logger.Log, apiv1 *Client, tracer *trace.Tracer) *MockNextMessageHandler {
	return &MockNextMessageHandler{
		log:    log,
		apiv1:  apiv1,
		tracer: tracer,
	}
}

func (h *MockNextMessageHandler) HandleMessage(ctx context.Context, message *sarama.ConsumerMessage) error {
	var mockNextRequest MockNextRequest
	if err := json.Unmarshal(message.Value, &mockNextRequest); err != nil {
		h.log.Error(err, "Failed to unmarshal message.Value from Kafka")
		return err
	}

	_, err := h.apiv1.MockNext(ctx, &mockNextRequest)
	if err != nil {
		h.log.Error(err, "Failed to MockNext")
		return err
	}
	return nil
}

// TODO(mk): REMOVE ME, JUST TO TEST A SECOND KAFKA CONSUMER GROUP FROM A DIFFERENT SERVICE
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
	h.log.Debug("Consuming message to debug", "message.Key", string(message.Key), "message.Topic", message.Topic, "message.Value", string(message.Value))
	return nil
}
