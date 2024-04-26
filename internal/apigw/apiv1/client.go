package apiv1

import (
	"context"
	"vc/internal/apigw/db"
	"vc/internal/apigw/queue"
	"vc/internal/apigw/simplequeue"
	"vc/pkg/kvclient"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/segmentio/kafka-go"
)

var (
	BuildVarGitCommit string
)

//	@title		Datastore API
//	@version	0.1.0
//	@BasePath	/api/v1

// Client holds the public api object
type Client struct {
	cfg         *model.Cfg
	db          *db.Service
	log         *logger.Log
	tp          *trace.Tracer
	kv          *kvclient.Client
	simpleQueue *simplequeue.Service
	queue       *queue.Service
	saveQueue   *kafka.Writer
}

// New creates a new instance of the public api
func New(ctx context.Context, kv *kvclient.Client, db *db.Service, simplequeue *simplequeue.Service, queue *queue.Service, tp *trace.Tracer, cfg *model.Cfg, logger *logger.Log) (*Client, error) {
	c := &Client{
		cfg:         cfg,
		db:          db,
		log:         logger,
		kv:          kv,
		tp:          tp,
		simpleQueue: simplequeue,
		queue:       queue,
	}

	//c.saveQueue = kafka.NewWriter(kafka.WriterConfig{
	//	Brokers:  c.cfg.Common.Queues.Kafka.Brokers,
	//	Topic:    "VCPersistentSave",
	//	Balancer: &kafka.LeastBytes{},
	//})
	//c.saveQueue.AllowAutoTopicCreation = true
	////defer kw.Close()

	c.log.Info("Started")

	return c, nil
}
