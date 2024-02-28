package main

import (
	"http-proxy-server/configs"
	"http-proxy-server/internal/app/proxy/pkg/app"
	"http-proxy-server/internal/app/proxy/pkg/logger"
	"http-proxy-server/internal/app/proxy/server"
	"http-proxy-server/internal/app/server/delivery"
	"http-proxy-server/internal/app/server/repository"
	"http-proxy-server/internal/app/server/usecase"
	"sync"
)

var loggerSingleton logger.Singleton

func main() {
	logger := loggerSingleton.GetLogger()
	app := app.Init()

	srvCfg := configs.GetHTTPSrvConfig(app.ConfigPath)
	tlsCfg := configs.GetTlsConfig(app.ConfigPath)
	apiCfg := configs.GetWebSrvConfig(app.ConfigPsx)

	requestRepo, _ := repository.GetUserRepo(&apiCfg, logger)
	requestUseCase := usecase.NewProxyUseCase(requestRepo)

	proxy := server.New(&srvCfg, &tlsCfg, &apiCfg, requestUseCase, logger)
	api := delivery.GetApi(requestUseCase, proxy, &srvCfg, logger)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := proxy.ListenAndServe(); err != nil {
			logger.Fatalln(err.Error())
		}
	}()

	go func() {
		defer wg.Done()
		if err := api.ListenAndServe(); err != nil {
			logger.Fatalln(err.Error())
		}
	}()

	wg.Wait()
}
