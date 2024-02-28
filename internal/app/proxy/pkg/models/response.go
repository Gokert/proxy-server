package models

import "net/http"

type ResponseInfo struct {
	Addr    string         `json:"addr"`
	Status  string         `json:"status"`
	Headers http.Header    `json:"headers"`
	Cookies []*http.Cookie `json:"cookies"`
	Body    string         `json:"body"`
}
