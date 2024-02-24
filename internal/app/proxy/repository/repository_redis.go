package repository

import (
	"context"
	"encoding/json"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"http-proxy-server/internal/app/proxy/config"
	"http-proxy-server/internal/pkg/models"
	"strings"
)

type RequestRepo struct {
	sessionRedisClient *redis.Client
}

func GetRequestRepo(cfg *config.DbRedisCfg, lg *logrus.Logger) (*RequestRepo, error) {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.Host,
		Password: cfg.Password,
		DB:       cfg.DbNumber,
	})

	ctx := context.Background()

	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		lg.Error("Ping error: ", err.Error())
		return nil, err
	}

	requestRepo := &RequestRepo{
		sessionRedisClient: redisClient,
	}

	return requestRepo, nil
}

func (repo *RequestRepo) SetRequestInfo(ctx context.Context, info *models.RequestInfo, lg *logrus.Logger) (bool, error) {

	infoBytes, err := json.Marshal(info)
	if err != nil {
		lg.Error("JSON marshaling error: ", err.Error())
		return false, err
	}

	parts := strings.Split(info.Addr, ":")

	err = repo.sessionRedisClient.HSet(ctx, "request:"+parts[0], parts[1], string(infoBytes)).Err()

	if err != nil {
		lg.Error("Set info error: ", err.Error())
		return false, err
	}

	isAdded, err := repo.CheckRequestInfo(ctx, info.Addr, lg)
	if err != nil {
		lg.Error("Check info error: ", err.Error())
		return false, err
	}

	return isAdded, nil
}

func (repo *RequestRepo) SetResponseInfo(ctx context.Context, info *models.ResponseInfo, lg *logrus.Logger) (bool, error) {
	infoBytes, err := json.Marshal(info)
	if err != nil {
		lg.Error("JSON marshaling error: ", err.Error())
		return false, err
	}

	parts := strings.Split(info.Addr, ":")

	err = repo.sessionRedisClient.HSet(ctx, "response:"+parts[0], parts[1], string(infoBytes)).Err()
	if err != nil {
		lg.Error("Set info error: ", err.Error())
		return false, err
	}

	isAdded, err := repo.CheckResponseInfo(ctx, info.Addr, lg)
	if err != nil {
		lg.Error("Check info error: ", err.Error())
		return false, err
	}

	return isAdded, nil
}

func (repo *RequestRepo) GetRequestInfo(ctx context.Context, address string, lg *logrus.Logger) (*models.RequestInfo, error) {
	return nil, nil
}

func (repo *RequestRepo) GetResponseInfo(ctx context.Context, address string, lg *logrus.Logger) (*models.RequestInfo, error) {
	return nil, nil
}

func (repo *RequestRepo) CheckRequestInfo(ctx context.Context, address string, lg *logrus.Logger) (bool, error) {
	parts := strings.Split(address, ":")

	_, err := repo.sessionRedisClient.HGet(ctx, "request:"+parts[0], parts[1]).Result()
	if err == redis.Nil {
		lg.Error("IP" + address + " not found")
		return false, err
	}

	if err != nil {
		lg.Error("Check request error: ", err.Error())
		return false, err
	}

	return true, nil
}

func (repo *RequestRepo) CheckResponseInfo(ctx context.Context, address string, lg *logrus.Logger) (bool, error) {
	parts := strings.Split(address, ":")

	_, err := repo.sessionRedisClient.HGet(ctx, "response:"+parts[0], parts[1]).Result()
	if err == redis.Nil {
		lg.Error("IP" + address + " not found")
		return false, err
	}

	if err != nil {
		lg.Error("Check response error: ", err.Error())
		return false, err
	}

	return true, nil
}
