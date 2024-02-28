package delivery

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"http-proxy-server/configs"
	proxy "http-proxy-server/internal/app/proxy/server"
	"http-proxy-server/internal/app/server/usecase"
	"http-proxy-server/pkg"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type API struct {
	requestUseCase usecase.IUseCase
	proxyServer    *proxy.ProxyServer
	cfg            *configs.HTTPSrvConfig
	lg             *logrus.Logger
	mx             *mux.Router
}

func GetApi(requestUseCase usecase.IUseCase, proxyServer *proxy.ProxyServer, cfg *configs.HTTPSrvConfig, lg *logrus.Logger) *API {
	api := &API{
		requestUseCase: requestUseCase,
		proxyServer:    proxyServer,
		cfg:            cfg,
		lg:             lg,
		mx:             mux.NewRouter(),
	}

	api.mx.HandleFunc("/requests", api.GetRequests)
	api.mx.HandleFunc("/requests/{id:[0-9]+}", api.GetRequest)
	api.mx.HandleFunc("/scan/{id:[0-9]+}", api.ScanRequest)
	api.mx.HandleFunc("/repeat/{id:[0-9]+}", api.RepeatRequest)

	return api
}

func (a *API) ListenAndServe() error {
	a.lg.Infof("start application-server listening at: " + a.cfg.WebPort)

	err := http.ListenAndServe(":"+a.cfg.WebPort, a.mx)
	if err != nil {
		a.lg.Error("Listen and serve error: ", err.Error())
		return err
	}

	return nil
}

func (a *API) ProxyRequest(w http.ResponseWriter, r *http.Request) {
	a.proxyHttpOrHttps(w, r, true)
}

func (a *API) proxyHttpOrHttps(w http.ResponseWriter, r *http.Request, save bool) {
	var err error

	if r.Method == http.MethodConnect {
		a.lg.Infof("HTTPS....")
		a.proxyServer.ProxyHTTPS(w, r)
		return
	}

	a.proxyServer.ProxyHTTP(w, r)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *API) GetRequest(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 32)
	selectedRequest, err := a.requestUseCase.GetRequestDataById(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	answer, err := json.Marshal(selectedRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(answer)
}

func (a *API) GetRequests(w http.ResponseWriter, r *http.Request) {
	selectedRequests, err := a.requestUseCase.GetAllRequestsData()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	answer, err := json.Marshal(selectedRequests)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(answer)
}

func (a *API) RepeatRequest(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 32)
	selectedRequest, err := a.requestUseCase.GetRequestById(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	a.proxyHttpOrHttps(w, &http.Request{
		Method: selectedRequest.Method,
		URL: &url.URL{
			Scheme: selectedRequest.Scheme,
			Host:   selectedRequest.Host,
			Path:   selectedRequest.Path,
		},
		Header: selectedRequest.Headers,
		Body:   ioutil.NopCloser(strings.NewReader(selectedRequest.Body)),
		Host:   r.Host,
	}, false)
}

func (a *API) ScanRequest(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 32)
	selectedRequest, err := a.requestUseCase.GetRequestById(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	request := &http.Request{
		Method: selectedRequest.Method,
		URL: &url.URL{
			Scheme: selectedRequest.Scheme,
			Host:   selectedRequest.Host,
			Path:   selectedRequest.Path,
		},
		Header: selectedRequest.Headers,
		Body:   ioutil.NopCloser(strings.NewReader(selectedRequest.Body)),
		Host:   r.Host,
	}
	params := url.Values{}
	for key, values := range selectedRequest.Params {
		for _, val := range values {
			params.Add(key, val)
		}
	}

	var flag bool
	for _, val := range pkg.GetParams() {
		randValue := pkg.RandStringRunes()
		newParams := params
		newParams.Add(val, randValue)
		request.URL.RawQuery = newParams.Encode()
		resp, err := http.DefaultTransport.RoundTrip(request)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		if strings.Contains(string(body), randValue) {
			w.Write([]byte(val + "-найден скрытый гет параметр\n"))
			flag = true
		}
	}
	if flag == false {
		w.Write([]byte("скрытые гет параметры не найдены\n"))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
}
