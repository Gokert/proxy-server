package server

import (
	"bufio"
	"crypto/tls"
	"http-proxy-server/internal/app/proxy/config"
	"http-proxy-server/internal/pkg/mw"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

type ProxyServer struct {
	tlsCfg config.TlsConfig
	srvCfg config.HTTPSrvConfig
	logger *logrus.Logger
}

func New(srvCfg config.HTTPSrvConfig, tlsCfg config.TlsConfig, logger *logrus.Logger) *ProxyServer {
	return &ProxyServer{
		srvCfg: srvCfg,
		tlsCfg: tlsCfg,
		logger: logger,
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

	w.WriteHeader(res.StatusCode)
	if _, err := io.Copy(w, res.Body); err != nil {
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

	log.Println("GERGREGRDTRT", response.Cookies())
	rawResponse, err := httputil.DumpResponse(response, true)
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
