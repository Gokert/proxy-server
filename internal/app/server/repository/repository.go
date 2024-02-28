package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/jackc/pgx/stdlib"
	"github.com/sirupsen/logrus"
	"http-proxy-server/configs"
	"http-proxy-server/internal/app/server/pkg/models"
)

type PostgresRepository struct {
	db *sql.DB
}

func GetUserRepo(config *configs.WebConfig, lg *logrus.Logger) (*PostgresRepository, error) {
	dsn := fmt.Sprintf("user=%s dbname=%s password= %s host=%s port=%d sslmode=%s",
		config.User, config.Dbname, config.Password, config.Host, config.Port, config.Sslmode)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		lg.Error("sql open error: ", "err", err.Error())
		return nil, fmt.Errorf("get user repo err: %w", err)
	}
	err = db.Ping()
	if err != nil {
		lg.Error("sql ping error: ", "err ", err.Error())
		return nil, fmt.Errorf("get user repo err: %w", err)
	}

	postgreDb := PostgresRepository{db: db}

	return &postgreDb, nil
}

func (r *PostgresRepository) InsertRequest(request *models.Request) error {
	byteHeaders, err := json.Marshal(request.Headers)
	if err != nil {
		return err
	}

	byteParams, err := json.Marshal(request.Params)
	if err != nil {
		return err
	}

	if err = r.db.QueryRow(
		"INSERT INTO requests(method, scheme, host, path, headers, body, params) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7) "+
			"RETURNING id",
		request.Method, request.Scheme, request.Host, request.Path,
		string(byteHeaders), request.Body, byteParams).
		Scan(&request.Id); err != nil {
		return err
	}

	return nil
}

func (r *PostgresRepository) InsertResponse(response *models.Response) error {
	byteHeaders, err := json.Marshal(response.Headers)
	if err != nil {
		return err
	}

	if err = r.db.QueryRow(
		"INSERT INTO responses(request_id, code, message, headers, body) "+
			"VALUES ($1, $2, $3, $4, $5) "+
			"RETURNING id",
		response.RequestId, response.Code, response.Message,
		string(byteHeaders), response.Body).
		Scan(&response.Id); err != nil {
		return err
	}

	return nil
}

func (r *PostgresRepository) GetRequestById(id int64) (*models.Request, error) {
	row := r.db.QueryRow("SELECT id, method, scheme, host, path, headers, body, params from requests where id = $1", id)

	var headersRaw, paramsRaw []byte
	selectedRequest := &models.Request{}
	err := row.Scan(
		&selectedRequest.Id,
		&selectedRequest.Method,
		&selectedRequest.Scheme,
		&selectedRequest.Host,
		&selectedRequest.Path,
		&headersRaw,
		&selectedRequest.Body,
		&paramsRaw,
	)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(headersRaw, &selectedRequest.Headers)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(paramsRaw, &selectedRequest.Params)
	if err != nil {
		return nil, err
	}

	return selectedRequest, nil
}

func (r *PostgresRepository) GetRequestDataById(id int64) (*models.RequestData, error) {
	row := r.db.QueryRow(
		"SELECT r.id, r.method, r.scheme, r.host, r.path, r.headers, r.body, r.params, "+
			"rp.id, rp.request_id, rp.code, rp.message, rp.headers, rp.body "+
			"from requests r "+
			"JOIN responses rp ON r.id = rp.request_id "+
			"where r.id = $1", id)

	var headersRaw, paramsRaw, respRaw []byte
	requestData := &models.RequestData{}
	err := row.Scan(
		&requestData.Request.Id,
		&requestData.Request.Method,
		&requestData.Request.Scheme,
		&requestData.Request.Host,
		&requestData.Request.Path,
		&headersRaw,
		&requestData.Request.Body,
		&paramsRaw,
		&requestData.Response.Id,
		&requestData.Response.RequestId,
		&requestData.Response.Code,
		&requestData.Response.Message,
		&respRaw,
		&requestData.Response.Body,
	)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(headersRaw, &requestData.Request.Headers)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(paramsRaw, &requestData.Request.Params)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(respRaw, &requestData.Response.Headers)
	if err != nil {
		return nil, err
	}

	return requestData, nil
}

func (r *PostgresRepository) GetAllRequestsData() ([]*models.RequestData, error) {
	rows, err := r.db.Query(
		"SELECT r.id, r.method, r.scheme, r.host, r.path, r.headers, r.body, r.params, " +
			"rp.id, rp.request_id, rp.code, rp.message, rp.headers, rp.body " +
			"from requests r " +
			"JOIN responses rp ON r.id = rp.request_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []*models.RequestData
	var headersRaw, paramsRaw, respRaw []byte
	for rows.Next() {
		requestData := &models.RequestData{}
		err = rows.Scan(
			&requestData.Request.Id,
			&requestData.Request.Method,
			&requestData.Request.Scheme,
			&requestData.Request.Host,
			&requestData.Request.Path,
			&headersRaw,
			&requestData.Request.Body,
			&paramsRaw,
			&requestData.Response.Id,
			&requestData.Response.RequestId,
			&requestData.Response.Code,
			&requestData.Response.Message,
			&respRaw,
			&requestData.Response.Body,
		)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(headersRaw, &requestData.Request.Headers)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(paramsRaw, &requestData.Request.Params)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(respRaw, &requestData.Response.Headers)
		if err != nil {
			return nil, err
		}

		requests = append(requests, requestData)
	}

	return requests, nil
}
