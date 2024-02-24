package server

import (
	"bufio"
	"crypto/tls"
	"http-proxy-server/internal/app/proxy/config"
	"http-proxy-server/internal/app/proxy/repository"
	"http-proxy-server/internal/pkg/models"
	"http-proxy-server/internal/pkg/mw"
	"io"
	"net/http"
	"net/http/httputil"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

type ProxyServer struct {
	tlsCfg   *config.TlsConfig
	srvCfg   *config.HTTPSrvConfig
	requests *repository.RequestRepo
	logger   *logrus.Logger
}

func New(srvCfg *config.HTTPSrvConfig, tlsCfg *config.TlsConfig, rdsCfg *config.DbRedisCfg, logger *logrus.Logger) *ProxyServer {
	requests, err := repository.GetRequestRepo(rdsCfg, logger)
	if err != nil {
		logger.Error("Request repository is not responding")
		return nil
	}

	return &ProxyServer{
		srvCfg:   srvCfg,
		tlsCfg:   tlsCfg,
		requests: requests,
		logger:   logger,
	}
}

func (ps ProxyServer) setMiddleware(handleFunc http.HandlerFunc) http.Handler {
	h := mw.AccessLog(ps.logger, http.HandlerFunc(handleFunc))
	return mw.RequestID(h)
}

func (ps ProxyServer) getRouter() http.Handler {
	router := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			ps.proxyHTTPS(w, r)
			return
		}

		ps.proxyHTTP(w, r)
	})

	return ps.setMiddleware(router)
}

func (ps ProxyServer) ListenAndServe() error {
	server := http.Server{
		Addr:    ps.srvCfg.Host + ":" + ps.srvCfg.Port,
		Handler: ps.getRouter(),
	}

	ps.logger.Infof("start listening at %s:%s", ps.srvCfg.Host, ps.srvCfg.Port)
	return server.ListenAndServe()
}

func (ps ProxyServer) proxyHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := mw.GetRequestID(r.Context())
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

	_, err = ps.SetResponseInfo(res, r, string(bodyResponse))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	bodyRequest, err := io.ReadAll(r.Body)
	if err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("round trip failed:", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	_, err = ps.SetRequestInfo(r, string(bodyRequest))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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

func (ps ProxyServer) proxyHTTPS(w http.ResponseWriter, r *http.Request) {
	reqID := mw.GetRequestID(r.Context())
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

	bodyResponse, err := io.ReadAll(response.Body)
	if err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("round trip failed:", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	_, err = ps.SetResponseInfo(response, r, string(bodyResponse))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	bodyRequest, err := io.ReadAll(r.Body)
	if err != nil {
		ps.logger.WithField("reqID", reqID).Errorln("round trip failed:", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	_, err = ps.SetRequestInfo(r, string(bodyRequest))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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

func (ps ProxyServer) SetRequestInfo(request *http.Request, body string) (bool, error) {
	requestInfo := &models.RequestInfo{
		Addr:       request.RemoteAddr,
		Method:     request.Method,
		Path:       request.URL.String(),
		GetParams:  "",
		Headers:    request.Header,
		Cookies:    request.Cookies(),
		PostParams: body,
	}

	_, err := ps.requests.SetRequestInfo(request.Context(), requestInfo, ps.logger)
	if err != nil {
		ps.logger.Println("Set error: ", err.Error())
		return false, err
	}

	return true, nil
}

func (ps ProxyServer) SetResponseInfo(response *http.Response, request *http.Request, body string) (bool, error) {
	responseInfo := &models.ResponseInfo{
		Addr:    request.RemoteAddr,
		Status:  response.Status,
		Headers: response.Header,
		Cookies: response.Cookies(),
		Body:    body,
	}

	_, err := ps.requests.SetResponseInfo(request.Context(), responseInfo, ps.logger)
	if err != nil {
		ps.logger.Println("Set error: ", err.Error())
		return false, err
	}

	return true, nil
}
