package messagebrokers

import "context"

type EventConsumer interface {
	Close(ctx context.Context) error
}
