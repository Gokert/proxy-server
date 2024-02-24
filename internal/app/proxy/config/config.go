package config

import (
	"gopkg.in/yaml.v2"
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

type TlsConfig struct {
	Script   string
	CertsDir string
	KeyFile  string
	CertFile string
}

type DbRedisCfg struct {
	Host     string `yaml:"host"`
	Password string `yaml:"password"`
	DbNumber int    `yaml:"db"`
	Timer    int    `yaml:"timer"`
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

func ReadRedisConfig() (*DbRedisCfg, error) {
	requsetConfig := DbRedisCfg{}
	requestFile, err := os.ReadFile("configs/redis_server.yaml")

	if err != nil {
		log.Println(err)
		return nil, err
	}

	err = yaml.Unmarshal(requestFile, &requsetConfig)
	if err != nil {
		return nil, err
	}

	return &requsetConfig, nil
}
