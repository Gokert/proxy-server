package app

import "flag"

type App struct {
	ConfigPath      string
	ConfigRedisPath string
	ConfigPsx       string
}

func Init() App {
	var app App

	flag.StringVar(&app.ConfigPath, "c", "configs/config.yaml", "path to config file")
	flag.StringVar(&app.ConfigRedisPath, "d", "configs/redis_server.yaml", "path to config redis file")
	flag.StringVar(&app.ConfigPsx, "a", "configs/psx_config.yaml", "path to config psx file")
	flag.Parse()

	return app
}
