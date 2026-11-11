// Copyright 2021 GoEdge CDN goedge.cdn@gmail.com. All rights reserved.

package serverconfigs

import (
	"errors"
	"net/http"
)

// HTTPAuthPolicy HTTP认证策略
type HTTPAuthPolicy struct {
	Id     int64                  `json:"id"`
	Name   string                 `json:"name"`
	IsOn   bool                   `json:"isOn"`
	Type   HTTPAuthType           `json:"type"`
	Params map[string]interface{} `json:"params"`

	method  HTTPAuthMethodInterface
	initErr error
}

// MatchRequest 检查是否匹配请求
func (this *HTTPAuthPolicy) MatchRequest(req *http.Request) bool {
	if !this.IsOn {
		return false
	}
	if this.method == nil || this.initErr != nil {
		// An enabled but invalid policy must enter Filter and reject the request
		// instead of being skipped as if its domain/extension did not match.
		return true
	}
	return this.method.MatchRequest(req)
}

// Filter 过滤
func (this *HTTPAuthPolicy) Filter(req *http.Request, subReqFunc func(subReq *http.Request) (status int, err error), formatter func(string) string) (ok bool, newURI string, uriChanged bool, err error) {
	if !this.IsOn {
		return true, "", false, nil
	}
	if this.initErr != nil {
		return false, "", false, this.initErr
	}
	if this.method == nil {
		return false, "", false, errors.New("enabled authentication policy is not initialized")
	}
	return this.method.Filter(req, subReqFunc, formatter)
}

// Method 获取认证实例
func (this *HTTPAuthPolicy) Method() HTTPAuthMethodInterface {
	return this.method
}
