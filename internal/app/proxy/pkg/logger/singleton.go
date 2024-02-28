package logger

import (
	"github.com/sirupsen/logrus"
	"sync"
)

type Singleton struct {
	once     sync.Once
	instance *logrus.Logger
}

func (s *Singleton) GetLogger() *logrus.Logger {
	s.once.Do(func() {
		s.instance = logrus.New()
		s.instance.SetLevel(logrus.InfoLevel)
		s.instance.Infoln("logrus initialized")
	})

	return s.instance
}
