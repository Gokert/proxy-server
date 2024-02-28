package pkg

import (
	"bufio"
	"log"
	"math/rand"
	"os"
	"time"
)

var (
	params      = make([]string, 0, 0)
	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
)

func init() {
	rand.Seed(time.Now().UnixNano())

	rootDir, _ := os.Getwd()
	inputFile, err := os.Open(rootDir + "/pkg/params.txt")
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		if scanner.Err() != nil {
			log.Fatal(scanner.Err().Error())
		}
		params = append(params, scanner.Text())
	}
}

func GetParams() []string {
	return params
}

func RandStringRunes() string {
	b := make([]rune, 10)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
