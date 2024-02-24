package app

import "flag"

type App struct {
	ConfigPath      string
	ConfigRedisPath string
}

func Init() App {
	var app App

	flag.StringVar(&app.ConfigPath, "c", "configs/config.yaml", "path to config file")
	flag.StringVar(&app.ConfigRedisPath, "d", "configs/redis_server.yaml", "path to config redis file")
	flag.Parse()

	return app
}
