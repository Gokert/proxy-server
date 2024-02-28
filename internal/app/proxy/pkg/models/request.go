package models

import "net/http"

type RequestInfo struct {
	Addr       string         `json:"addr"`
	Method     string         `json:"method"`
	Path       string         `json:"path"`
	GetParams  string         `json:"get_params"`
	Headers    http.Header    `json:"headers"`
	Cookies    []*http.Cookie `json:"cookies"`
	PostParams string         `json:"post_params"`
}
