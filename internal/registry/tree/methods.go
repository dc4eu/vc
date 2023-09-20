package tree

import (
	"vc/pkg/model"

	"github.com/wealdtech/go-merkletree"
)

// Remove removes an entity from the registry
func (s *Service) Remove(value string) error {
	return s.db.Remove(value, &model.Leaf{})
}

// Insert inserts a new entity into the registry
func (s *Service) Insert(value string) error {
	return s.db.Insert(&model.Leaf{Value: []byte(value)})
}

// Validate validates an entity in the registry
func (s *Service) Validate(value string) (bool, error) {
	proof, err := s.smt.GenerateProof([]byte(value))
	if err != nil {
		return false, err
	}
	return merkletree.VerifyProof([]byte(value), proof, s.rootHash)
}
