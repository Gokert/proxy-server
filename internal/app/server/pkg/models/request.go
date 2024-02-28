package models

type Request struct {
	Id      int64               `json:"id"`
	Method  string              `json:"method"`
	Scheme  string              `json:"scheme"`
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Params  map[string][]string `json:"params"`
	Body    string              `json:"body"`
}

type Response struct {
	Id        int64               `json:"id"`
	RequestId int64               `json:"request_id"`
	Code      int                 `json:"code"`
	Message   string              `json:"message"`
	Headers   map[string][]string `json:"headers"`
	Body      string              `json:"body"`
}

type RequestData struct {
	Request  Request  `json:"request"`
	Response Response `json:"response"`
}
