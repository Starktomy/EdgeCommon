// Copyright 2021 GoEdge CDN goedge.cdn@gmail.com. All rights reserved.

package serverconfigs

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/TeaOSLab/EdgeCommon/pkg/rpcauth"
)

// HTTPAuthSubRequestMethod 使用URL认证
type HTTPAuthSubRequestMethod struct {
	HTTPAuthBaseMethod

	URL    string `json:"url"`
	Method string `json:"method"`

	// TODO 增加自定义Header、超时、证书等

	isFullURL  bool
	httpClient *http.Client
	origin     string
}

func NewHTTPAuthSubRequestMethod() *HTTPAuthSubRequestMethod {
	return &HTTPAuthSubRequestMethod{}
}

// Init 初始化
func (this *HTTPAuthSubRequestMethod) Init(params map[string]any) error {
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return err
	}
	err = json.Unmarshal(paramsJSON, this)
	if err != nil {
		return err
	}

	// 是否是完整的URL
	this.isFullURL = false
	this.httpClient = nil
	this.origin = ""
	if regexp.MustCompile(`^(?i)(http|https)://`).MatchString(this.URL) {
		this.isFullURL = true
		target, err := url.Parse(this.URL)
		if err != nil || target.Hostname() == "" || target.User != nil {
			return errors.New("authentication subrequest requires an HTTP(S) URL without embedded credentials")
		}
		client, err := newHTTPAuthSubRequestClient(target, os.Getenv("EDGE_AUTH_CA_FILE"))
		if err != nil {
			return err
		}
		this.httpClient = client
		this.origin = httpAuthSubRequestOrigin(target)
	} else {
		if len(this.URL) == 0 || this.URL[0] != '/' {
			this.URL = "/" + this.URL
		}
	}

	return nil
}

// Filter 过滤
func (this *HTTPAuthSubRequestMethod) Filter(req *http.Request, doSubReq func(subReq *http.Request) (status int, err error), formatter func(string) string) (ok bool, newURI string, uriChanged bool, err error) {
	var method = this.Method
	if len(method) == 0 {
		method = req.Method
	}

	var url = formatter(this.URL)
	var scheme = "http"
	if req.TLS != nil {
		scheme = "https"
	}
	var host = req.URL.Host
	if len(host) == 0 {
		host = req.Host
	}
	if !this.isFullURL {
		url = scheme + "://" + host + url
	}
	newReq, err := http.NewRequestWithContext(req.Context(), method, url, nil)
	if err != nil {
		return false, "", false, err
	}
	newReq.Header = req.Header.Clone()
	if newReq.Header == nil {
		newReq.Header = make(http.Header)
	}
	newReq.Header.Del("Connection")

	if !this.isFullURL {
		status, err := doSubReq(newReq)
		if err != nil {
			return false, "", false, err
		}
		return status >= 200 && status < 300, "", false, nil
	}

	if this.httpClient == nil || newReq.URL.User != nil || httpAuthSubRequestOrigin(newReq.URL) != this.origin {
		return false, "", false, errors.New("authentication subrequest must keep its configured origin")
	}
	// TODO 需要将Header和StatusCode、ResponseBody输出到客户端
	newReq.Header.Set("Referer", scheme+"://"+host+req.URL.RequestURI())
	resp, err := this.httpClient.Do(newReq)
	if err != nil {
		return false, "", false, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	return resp.StatusCode >= 200 && resp.StatusCode < 300, "", false, nil
}

func newHTTPAuthSubRequestClient(target *url.URL, caPath string) (*http.Client, error) {
	if target == nil || (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" || target.User != nil {
		return nil, errors.New("invalid authentication subrequest target")
	}
	tlsConfig, err := rpcauth.VerifiedTLSConfig(target.Hostname(), caPath)
	if err != nil {
		return nil, err
	}
	// Keep a client per configured method so an explicit private CA never falls
	// back to a previously created global transport with weaker trust settings.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	transport.Proxy = nil
	origin := httpAuthSubRequestOrigin(target)
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 10 || request.URL.User != nil || httpAuthSubRequestOrigin(request.URL) != origin {
				return errors.New("authentication subrequest redirect left its configured origin")
			}
			return nil
		},
	}, nil
}

func httpAuthSubRequestOrigin(target *url.URL) string {
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return strings.ToLower(target.Scheme) + "://" + net.JoinHostPort(strings.ToLower(target.Hostname()), port)
}
