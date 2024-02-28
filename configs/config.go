package configs

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type HTTPSrvConfig struct {
	ProxyPort string
	ProxyHost string
	WebPort   string
	WebHost   string
}

type WebConfig struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Dbname   string `yaml:"dbname"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Sslmode  string `yaml:"sslmode"`
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
		ProxyPort: v.GetString("proxy.port"),
		ProxyHost: v.GetString("proxy.host"),
		WebPort:   v.GetString("webapi.port"),
		WebHost:   v.GetString("proxy.host"),
	}
}

func GetWebSrvConfig(cfgPath string) WebConfig {
	v := viper.GetViper()
	v.SetConfigFile(cfgPath)
	v.SetConfigType(strings.TrimPrefix(filepath.Ext(cfgPath), "."))

	if err := viper.ReadInConfig(); err != nil {
		log.Fatal(err)
	}

	return WebConfig{
		User:     v.GetString("user"),
		Password: v.GetString("password"),
		Dbname:   v.GetString("dbname"),
		Host:     v.GetString("host"),
		Port:     v.GetInt("port"),
		Sslmode:  v.GetString("sslmode"),
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
