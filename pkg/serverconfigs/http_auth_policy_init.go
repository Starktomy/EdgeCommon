// Copyright 2021 GoEdge CDN goedge.cdn@gmail.com. All rights reserved.
//go:build !plus

package serverconfigs

import (
	"errors"
)

// Init 初始化
func (this *HTTPAuthPolicy) Init() error {
	this.method = nil
	this.initErr = nil
	switch this.Type {
	case HTTPAuthTypeBasicAuth:
		this.method = NewHTTPAuthBasicMethod()
	case HTTPAuthTypeSubRequest:
		this.method = NewHTTPAuthSubRequestMethod()
	}

	if this.method == nil {
		this.initErr = errors.New("unknown auth method '" + this.Type + "'")
		return this.initErr
	}
	err := this.method.Init(this.Params)
	if err != nil {
		this.initErr = err
		this.method = nil
		return err
	}

	return nil
}
