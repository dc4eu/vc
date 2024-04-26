package queue

import (
	"context"
	"encoding/json"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel/codes"
)

// QueueingVCDeleteDocumentV0 is the queueing service for VCSaveUploadV0
type QueueingVCDeleteDocumentV0 struct {
	service *Service
	log     *logger.Log
	reader  *kafka.Reader
}

// newQueueingVCDeleteUploadV0 creates a new queueing service for VCSaveUploadV0
func newQueueingVCDeleteUploadV0(ctx context.Context, service *Service, topic, groupID string, log *logger.Log) {
	q := &QueueingVCDeleteDocumentV0{
		service: service,
		log:     log,
	}

	q.reader = q.service.newConsumer(ctx, topic, groupID)

	q.service.ConsumerServices[topic] = q

	go func() {
		if err := q.worker(ctx); err != nil {
			q.log.Error(err, "Worker failed")
		}
	}()

	q.log.Info("Started")
}

func (q *QueueingVCDeleteDocumentV0) worker(ctx context.Context) error {
	ctx, span := q.service.tp.Start(ctx, "queue:QueuingVCDeleteDocumentV0:Worker")
	defer span.End()

	var (
		msgChan = make(chan kafka.Message)
		errChan = make(chan error)
	)

	go func() {
		for {
			msg, err := q.reader.ReadMessage(ctx)
			if err != nil {
				errChan <- err
			}
			msgChan <- msg
		}
	}()

	for {
		select {
		case err := <-errChan:
			q.log.Error(err, "worker failed")
			return err
		case msg := <-msgChan:
			q.log.Info("received message", "key", msg.Key)
			document := &model.MetaData{}
			if err := json.Unmarshal([]byte(msg.Value), document); err != nil {
				span.SetStatus(codes.Error, err.Error())
				q.log.Error(err, "Unmarshal failed")
			}
			if err := q.service.db.VCDatastoreColl.Delete(ctx, document); err != nil {
				span.SetStatus(codes.Error, err.Error())
				q.log.Error(err, "Save upload failed")
			}

		case <-ctx.Done():
			q.log.Info("Stopped worker")
			span.SetStatus(codes.Error, "context done")
			return nil
		}
	}
}

func (q *QueueingVCDeleteDocumentV0) close(ctx context.Context) error {
	if err := q.reader.Close(); err != nil {
		return err
	}

	q.log.Info("closing consumer service")
	return nil
}
