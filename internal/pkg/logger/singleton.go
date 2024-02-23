package logger

import (
	"sync"

	"github.com/sirupsen/logrus"
)

type Singleton struct {
	once     sync.Once
	instance *logrus.Logger
}

func (s *Singleton) GetLogger() *logrus.Logger {
	s.once.Do(func() {
		s.instance = logrus.New()
		s.instance.SetLevel(logrus.InfoLevel)
		// s.instance.Formatter = &logrus.JSONFormatter{}
		s.instance.Infoln("logrus initialized")
	})

	return s.instance
}
