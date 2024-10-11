package tree

import (
	"context"
	"sync"
	"time"
	"vc/internal/registry/db"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/wealdtech/go-merkletree"
)

// Service is the merkel tree client
type Service struct {
	smt      *merkletree.MerkleTree
	log      *logger.Log
	cfg      *model.Cfg
	rootHash []byte
	data     [][]byte
	quitChan chan struct{}
	ticker   *time.Ticker
	db       *db.Service
	wg       *sync.WaitGroup
}

// New creates a new merkel tree client
func New(ctx context.Context, wg *sync.WaitGroup, db *db.Service, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	s := &Service{
		log:      log.New("tree"),
		cfg:      cfg,
		db:       db,
		wg:       wg,
		quitChan: make(chan struct{}),
		ticker:   time.NewTicker(time.Duration(cfg.Registry.SMT.UpdatePeriodicity) * time.Second),
	}

	if err := s.load(); err != nil {
		return nil, err
	}

	s.wg.Add(1)
	go func() {
		for {
			select {
			case <-s.ticker.C:
				s.log.Info("merkel tree update")
				if err := s.load(); err != nil {
					s.log.Error(err, "merkel tree update failed")
					s.quitChan <- struct{}{}
				}
			case <-s.quitChan:
				s.log.Info("Stop updating tree")
				s.ticker.Stop()
				s.wg.Done()
				return
			}
		}
	}()

	s.log.Info("Started")

	return s, nil
}

func (s *Service) load() error {
	data := [][]byte{}

	leafs := &model.Leafs{}
	err := s.db.Find(leafs)
	if err != nil {
		return err
	}

	if leafs.Empty() {
		s.log.Info("DB is empty, using init data")
		data = [][]byte{
			[]byte(s.cfg.Registry.SMT.InitLeaf),
		}
	} else {
		data = leafs.Array()
	}

	s.smt, err = merkletree.New(data)
	if err != nil {
		return err
	}

	s.rootHash = s.smt.Root()
	return nil
}

// Close closes the merkel tree service
func (s *Service) Close(ctx context.Context) error {
	s.quitChan <- struct{}{}

	s.wg.Wait()

	s.log.Info("Stopped")
	return nil
}
