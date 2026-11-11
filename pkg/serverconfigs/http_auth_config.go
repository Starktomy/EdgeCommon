// Copyright 2021 GoEdge CDN goedge.cdn@gmail.com. All rights reserved.

package serverconfigs

import "errors"

// HTTPAuthConfig 认证配置
type HTTPAuthConfig struct {
	IsPrior    bool                 `yaml:"isPrior" json:"isPrior"`
	IsOn       bool                 `yaml:"isOn" json:"isOn"`
	PolicyRefs []*HTTPAuthPolicyRef `yaml:"policyRefs" json:"policyRefs"`
}

func (this *HTTPAuthConfig) Init() error {
	for _, ref := range this.PolicyRefs {
		if ref == nil {
			return errors.New("authentication configuration contains a nil policy reference")
		}
		err := ref.Init()
		if err != nil {
			return err
		}
	}
	return nil
}
