// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"reflect"
	"sort"
	"testing"
)

type fields struct {
	config *Config
}

type args struct {
	resolvers, trustedResolvers []string
}

var tests = []struct {
	name   string
	fields fields
	args   args
}{
	{
		name:   "success",
		fields: fields{config: &Config{}},
		args: args{
			resolvers:        []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"},
			trustedResolvers: DefaultBaselineResolvers,
		},
	},
}

func TestConfigSetResolvers(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fields.config.SetResolvers(tt.args.resolvers...)

			sort.Strings(tt.fields.config.Resolvers)
			sort.Strings(tt.args.resolvers)
			if !reflect.DeepEqual(tt.args.resolvers, tt.fields.config.Resolvers) {
				t.Errorf("SetResolvers() = %v, want %v",
					tt.args.resolvers, tt.fields.config.Resolvers)
			}
		})
	}
}

func TestConfigSetTrustedResolvers(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fields.config.SetTrustedResolvers(tt.args.trustedResolvers...)

			sort.Strings(tt.fields.config.TrustedResolvers)
			sort.Strings(tt.args.trustedResolvers)
			if !reflect.DeepEqual(tt.args.trustedResolvers, tt.fields.config.TrustedResolvers) {
				t.Errorf("SetTrustedResolvers() = %v, want %v",
					tt.args.trustedResolvers, tt.fields.config.TrustedResolvers)
			}
		})
	}
}

func BenchmarkTestConfigSetResolvers(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, tt := range tests {
			b.Run(tt.name, func(b *testing.B) {
				tt.fields.config.SetResolvers(tt.args.resolvers...)
			})
		}
	}
}

func BenchmarkTestConfigSetTrustedResolvers(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, tt := range tests {
			b.Run(tt.name, func(b *testing.B) {
				tt.fields.config.SetTrustedResolvers(tt.args.trustedResolvers...)
			})
		}
	}
}

func TestGetPublicDNSResolvers(t *testing.T) {
	err := GetPublicDNSResolvers()
	if err != nil {
		t.Error(err)
		return
	}
	if len(PublicResolvers) <= 0 {
		t.Error("No resolvers obtained")
	} else if PublicResolvers == nil {
		t.Error("PublicResolvers is a nil slice")
	}
}

func BenchmarkTestPublicDNSResolvers(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := GetPublicDNSResolvers()
		if err != nil {
			b.Error(err)
			return
		}
	}
}
