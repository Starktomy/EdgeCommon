// Copyright 2021 GoEdge CDN goedge.cdn@gmail.com. All rights reserved.

package serverconfigs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPAuthRequestMethod_Filter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.Header.Get("Hello") != "World" {
			t.Error("authentication subrequest lost its method or headers")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	method := &HTTPAuthSubRequestMethod{}
	err := method.Init(map[string]interface{}{
		"url":    server.URL,
		"method": http.MethodPost,
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://teaos.cn/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Hello", "World")
	req.Header.Set("User-Agent", "GoEdge/1.0")
	b, uri, uriChanged, err := method.Filter(req, func(subReq *http.Request) (status int, err error) {
		return
	}, func(s string) string {
		return s
	})
	if err != nil {
		t.Fatal(err)
	}
	if !b {
		t.Fatal("successful authentication subrequest was rejected")
	}
	t.Log("result:", b, uri, uriChanged)
}

func TestHTTPAuthRequestMethod_Filter_Path(t *testing.T) {
	method := &HTTPAuthSubRequestMethod{}
	err := method.Init(map[string]interface{}{
		"url":    "/hello?${var}",
		"method": http.MethodGet,
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://teaos.cn/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Hello", "World")
	req.Header.Set("User-Agent", "GoEdge/1.0")
	b, uri, uriChanged, err := method.Filter(req, func(subReq *http.Request) (status int, err error) {
		status = http.StatusNoContent
		t.Log("execute sub request:", subReq.URL, status)
		return
	}, func(s string) string {
		return strings.ReplaceAll(s, "${var}", "$VAR")
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("result:", b, uri, uriChanged)
}
