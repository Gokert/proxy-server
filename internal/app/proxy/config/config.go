package config

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type HTTPSrvConfig struct {
	Port string
	Host string
}

func GetHTTPSrvConfig(cfgPath string) HTTPSrvConfig {
	v := viper.GetViper()
	v.SetConfigFile(cfgPath)
	v.SetConfigType(strings.TrimPrefix(filepath.Ext(cfgPath), "."))

	if err := viper.ReadInConfig(); err != nil {
		log.Fatal(err)
	}

	return HTTPSrvConfig{
		Port: v.GetString("proxy.port"),
		Host: v.GetString("proxy.host"),
	}
}

type TlsConfig struct {
	Script   string
	CertsDir string
	KeyFile  string
	CertFile string
}

func GetTlsConfig(cfgPath string) TlsConfig {
	v := viper.GetViper()
	v.SetConfigFile(cfgPath)
	v.SetConfigType(strings.TrimPrefix(filepath.Ext(cfgPath), "."))

	if err := viper.ReadInConfig(); err != nil {
		log.Fatal(err)
	}

	currDir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	certsDirRelPath := v.GetString("proxy.certs_dir")

	return TlsConfig{
		Script:   filepath.Join(currDir, v.GetString("proxy.certs_gen_script")),
		CertsDir: filepath.Join(currDir, certsDirRelPath),
		KeyFile:  filepath.Join(currDir, certsDirRelPath, v.GetString("proxy.key_file")),
		CertFile: filepath.Join(currDir, certsDirRelPath, v.GetString("proxy.cert_file")),
	}
}
