package db

// Find finds a model, or error
func (s *Service) Find(model any) error {
	tx := s.db.Find(model)
	if tx.Error != nil {
		return tx.Error
	}
	return nil
}

// Remove removes a model, or error
func (s *Service) Remove(q string, model any) error {
	tx := s.db.Where("value = ?", []byte(q)).Delete(model)
	if tx.Error != nil {
		return tx.Error
	}
	return nil
}

// Insert inserts a model, or error
func (s *Service) Insert(model any) error {
	tx := s.db.Create(model)
	if tx.Error != nil {
		return tx.Error
	}
	return nil
}
