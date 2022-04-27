// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"reflect"
	"sort"
	"testing"
)

var cfg = NewConfig()

func TestConfigSetResolvers(t *testing.T) {
	type fields struct {
		config *Config
	}
	type args struct {
		resolvers []string
	}

	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name:   "success",
			fields: fields{config: &Config{}},
			args: args{
				resolvers: []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fields.config.SetResolvers(tt.args.resolvers...)

			sort.Strings(tt.fields.config.Resolvers)
			if !reflect.DeepEqual(tt.args.resolvers, tt.fields.config.Resolvers) {
				t.Errorf("SetResolvers() = %v, want %v",
					tt.args.resolvers, tt.fields.config.Resolvers)
			}
		})
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
