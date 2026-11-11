// Copyright 2021 GoEdge CDN goedge.cdn@gmail.com. All rights reserved.

package serverconfigs

import "errors"

// HTTPAuthPolicyRef 认证策略引用
type HTTPAuthPolicyRef struct {
	IsOn         bool            `yaml:"isOn" json:"isOn"`
	AuthPolicyId int64           `yaml:"authPolicyId" json:"authPolicyId"`
	AuthPolicy   *HTTPAuthPolicy `yaml:"authPolicy" json:"authPolicy"`
}

func (this *HTTPAuthPolicyRef) Init() error {
	if this.IsOn && this.AuthPolicy == nil {
		return errors.New("enabled authentication reference has no policy")
	}
	if this.AuthPolicy != nil {
		err := this.AuthPolicy.Init()
		if err != nil {
			return err
		}
	}
	return nil
}
