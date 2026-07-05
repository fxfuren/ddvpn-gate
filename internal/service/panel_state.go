package service

import (
	"sync"
	"time"
)

type PanelState struct {
	mu           sync.RWMutex
	isAvailable  bool
	lastError    error
	lastErrorAt  time.Time
	lastSuccess  time.Time
}

func NewPanelState() *PanelState {
	return &PanelState{
		isAvailable: true, // assume available initially
	}
}

func (s *PanelState) IsAvailable() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isAvailable
}

func (s *PanelState) MarkUnavailable(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isAvailable = false
	s.lastError = err
	s.lastErrorAt = time.Now()
}

func (s *PanelState) MarkAvailable() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isAvailable = true
	s.lastSuccess = time.Now()
	s.lastError = nil
}

func (s *PanelState) LastError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastError
}
