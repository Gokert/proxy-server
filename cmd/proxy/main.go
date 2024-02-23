package main

import (
	"http-proxy-server/internal/app/proxy/config"
	"http-proxy-server/internal/app/proxy/server"
	"http-proxy-server/internal/pkg/app"
	"http-proxy-server/internal/pkg/logger"
)

var loggerSingleton logger.Singleton

func main() {
	app := app.Init()

	srvCfg := config.GetHTTPSrvConfig(app.ConfigPath)
	tlsCfg := config.GetTlsConfig(app.ConfigPath)

	logger := loggerSingleton.GetLogger()

	srv := server.New(srvCfg, tlsCfg, logger)
	if err := srv.ListenAndServe(); err != nil {
		logger.Fatalln(err.Error())
	}
}
