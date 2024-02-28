package server

import (
	"bufio"
	"crypto/tls"
	"http-proxy-server/configs"
	mw2 "http-proxy-server/internal/app/proxy/pkg/mw"
	"http-proxy-server/internal/app/server/pkg/models"
	repo "http-proxy-server/internal/app/server/repository"
	"http-proxy-server/internal/app/server/usecase"
	//"http-proxy-server/internal/app/proxy/repository"
	"io"
	"net/http"
	"net/http/httputil"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

type ProxyServer struct {
	requestUseCase usecase.IUseCase
	tlsCfg         *configs.TlsConfig
	srvCfg         *configs.HTTPSrvConfig
	requests       *repo.PostgresRepository
	logger         *logrus.Logger
}

func New(srvCfg *configs.HTTPSrvConfig, tlsCfg *configs.TlsConfig, psxCfg *configs.WebConfig, requestUseCase usecase.IUseCase, logger *logrus.Logger) *ProxyServer {
	requests, err := repo.GetUserRepo(psxCfg, logger)
	if err != nil {
		logger.Error("Request repository is not responding")
		return nil
	}

	return &ProxyServer{
		requestUseCase: requestUseCase,
		srvCfg:         srvCfg,
		tlsCfg:         tlsCfg,
		requests:       requests,
		logger:         logger,
	}
}

func (ps ProxyServer) setMiddleware(handleFunc http.HandlerFunc) http.Handler {
	h := mw2.AccessLog(ps.logger, http.HandlerFunc(handleFunc))
	return mw2.RequestID(h)
}

func (ps ProxyServer) getRouter() http.Handler {
	router := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			ps.ProxyHTTPS(w, r)
			return
		}

		ps.ProxyHTTP(w, r)
	})

	return ps.setMiddleware(router)
}

func (ps ProxyServer) ListenAndServe() error {
	server := http.Server{
		Addr:    ps.srvCfg.ProxyHost + ":" + ps.srvCfg.ProxyPort,
		Handler: ps.getRouter(),
	}

	ps.logger.Infof("start proxy-server listening at %s:%s", ps.srvCfg.ProxyHost, ps.srvCfg.ProxyPort)
	return server.ListenAndServe()
}

func (ps ProxyServer) ProxyHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := mw2.GetRequestID(r.Context())
	ps.logger.WithField("reqID", reqID).Infoln("entered in proxyHTTP")

	r.Header.Del("Proxy-Connection")

	res, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("round trip failed:", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	defer res.Body.Close()
	res.Cookies()

	for key, values := range res.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	bodyResponse, err := io.ReadAll(res.Body)
	if err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("round trip failed:", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	bodyRequest, err := io.ReadAll(r.Body)
	if err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("round trip failed:", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	ps.logger.Println(reqID)

	request := &models.Request{
		Method:  r.Method,
		Scheme:  "http",
		Host:    r.Host,
		Path:    r.URL.Path,
		Headers: r.Header,
		Params:  r.URL.Query(),
		Body:    string(bodyRequest),
	}

	err = ps.requestUseCase.SaveRequest(request)
	if err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("SaveRequest error: ", err.Error())
	}

	response := &models.Response{
		RequestId: request.Id,
		Code:      res.StatusCode,
		Message:   res.Status,
		Headers:   res.Header,
		Body:      string(bodyResponse),
	}

	err = ps.requestUseCase.SaveResponse(response)
	if err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("SaveResponse error: ", err.Error())
	}

	w.WriteHeader(res.StatusCode)
	_, err = w.Write(bodyResponse)
	if err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("io copy failed:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ps.logger.WithField("reqID", reqID).Infoln("exited from proxyHTTP")
}

func (ps ProxyServer) ProxyHTTPS(w http.ResponseWriter, r *http.Request) {
	reqID := mw2.GetRequestID(r.Context())
	ps.logger.WithField("reqID", reqID).Infoln("entered in proxyHTTPS")

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		ps.logger.WithField("reqID", reqID).Errorln("hijacking not supported")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	localConn, _, err := hijacker.Hijack()
	if err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("hijack failed:", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	if _, err := localConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("write to local connection failed:", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		localConn.Close()
		return
	}

	defer localConn.Close()

	tlsConfig, err := ps.hostTLSConfig(strings.Split(r.Host, ":")[0])
	if err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("hostTLSConfig failed:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tlsLocalConn := tls.Server(localConn, tlsConfig)
	defer tlsLocalConn.Close()
	if err := tlsLocalConn.Handshake(); err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("tls handshake failed:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	remoteConn, err := tls.Dial("tcp", r.Host, tlsConfig)
	if err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("tls dial failed:", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	defer remoteConn.Close()

	reader := bufio.NewReader(tlsLocalConn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("read request failed:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	requestByte, err := httputil.DumpRequest(request, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = remoteConn.Write(requestByte)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	serverReader := bufio.NewReader(remoteConn)
	response, err := http.ReadResponse(serverReader, request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rawResponse, err := httputil.DumpResponse(response, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	requestInfo := &models.Request{
		Method:  r.Method,
		Scheme:  "https",
		Host:    r.Host,
		Path:    r.URL.Path,
		Headers: r.Header,
		Params:  r.URL.Query(),
		Body:    string(requestByte),
	}

	err = ps.requestUseCase.SaveRequest(requestInfo)
	if err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("SaveRequest error: ", err.Error())
	}

	responseInfo := &models.Response{
		RequestId: requestInfo.Id,
		Code:      response.StatusCode,
		Message:   response.Status,
		Headers:   response.Header,
		Body:      string(rawResponse),
	}

	err = ps.requestUseCase.SaveResponse(responseInfo)
	if err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("SaveResponse error: ", err.Error())
	}

	_, err = tlsLocalConn.Write(rawResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (ps ProxyServer) hostTLSConfig(host string) (*tls.Config, error) {
	if err := exec.Command(ps.tlsCfg.Script, host).Run(); err != nil {
		ps.logger.WithFields(logrus.Fields{
			"script": ps.tlsCfg.Script,
			"host":   host,
		}).Errorln("exec command failed:", err.Error())

		return nil, err
	}

	tlsCert, err := tls.LoadX509KeyPair(ps.tlsCfg.CertFile, ps.tlsCfg.KeyFile)
	if err != nil {
		ps.logger.WithFields(logrus.Fields{
			"cert file": ps.tlsCfg.CertFile,
			"key file":  ps.tlsCfg.KeyFile,
		}).Errorln("LoadX509KeyPair failed:", err.Error())

		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}, nil
}
