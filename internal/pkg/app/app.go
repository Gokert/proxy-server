package app

import "flag"

type App struct {
	ConfigPath string
}

func Init() App {
	var app App

	flag.StringVar(&app.ConfigPath, "c", "configs/config.yaml", "path to config file")
	flag.Parse()

	return app
}
