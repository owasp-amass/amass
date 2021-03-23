package format

import (
	"testing"
)

func TestNilParseStrings(t *testing.T) {
	const want = ""
	got := (*ParseStrings)(nil).String()
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestParseStrings(t *testing.T) {
	cases := []struct {
		label string
		input string
		ok    bool
		want  string
	}{
		{
			label: "empty input",
			input: "",
		}, {
			label: "",
			input: "234,foo,bar",
			ok:    true,
			want:  "234,foo,bar",
		}, {
			label: "extra comma",
			input: "234,foo,bar,",
			ok:    true,
			want:  "234,foo,bar,",
		}, {
			label: "with whitespace",
			input: "234  , foo ,\tbar",
			ok:    true,
			want:  "234,foo,bar",
		},
	}
	for _, c := range cases {
		f := func(t *testing.T) {
			var ints ParseStrings
			err := ints.Set(c.input)
			if err != nil && c.ok {
				t.Errorf("got %v; want <nil>", err)
			}
			if err == nil && !c.ok {
				t.Error("got <nil>; want some error")
			}
			if err == nil && c.ok {
				got := ints.String()
				if got != c.want {
					t.Errorf("got %q; want %q", got, c.want)
				}
			}
		}
		t.Run(c.label, f)
	}
}

func TestNilParseInts(t *testing.T) {
	const want = ""
	got := (*ParseInts)(nil).String()
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestParseInts(t *testing.T) {
	cases := []struct {
		label string
		input string
		ok    bool
		want  string
	}{
		{
			label: "empty input",
			input: "",
		}, {
			label: "invalid int",
			input: "1,sdfg,2,3",
		}, {
			label: "extraneous comma",
			input: "-1,2,,",
		}, {
			label: "without whitespace",
			input: "-1,10,42",
			ok:    true,
			want:  "-1,10,42",
		}, {
			label: "with whitespace",
			input: "-1, 10 ,\t42",
			ok:    true,
			want:  "-1,10,42",
		},
	}
	for _, c := range cases {
		f := func(t *testing.T) {
			var ints ParseInts
			err := ints.Set(c.input)
			if err != nil && c.ok {
				t.Errorf("got %v; want <nil>", err)
			}
			if err == nil && !c.ok {
				t.Error("got <nil>; want some error")
			}
			if err == nil && c.ok {
				got := ints.String()
				if got != c.want {
					t.Errorf("got %q; want %q", got, c.want)
				}
			}
		}
		t.Run(c.label, f)
	}
}

func TestNilParseIPs(t *testing.T) {
	const want = ""
	got := (*ParseIPs)(nil).String()
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestParseIPs(t *testing.T) {
	cases := []struct {
		label string
		input string
		ok    bool
		want  string
	}{
		{
			label: "empty input",
			input: "",
		}, {
			label: "single valid IPv4",
			input: "127.0.0.1",
			ok:    true,
			want:  "127.0.0.1",
		}, {
			label: "single valid IPv6",
			input: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			ok:    true,
			want:  "2001:db8:85a3::8a2e:370:7334",
		}, {
			label: "single IPv4 byte overflow",
			input: "256.0.0.1",
		}, {
			label: "valid compact range",
			input: "127.0.0.1-3",
			ok:    true,
			want:  "127.0.0.1,127.0.0.2,127.0.0.3",
		}, {
			label: "valid range",
			input: "127.0.0.1-127.0.0.3",
			ok:    true,
			want:  "127.0.0.1,127.0.0.2,127.0.0.3",
		}, {
			label: "empty range",
			input: "127.0.0.2-127.0.0.1",
		}, {
			label: "range end overflows byte",
			input: "0.0.0.0-256",
			ok:    true,
			want:  "0.0.0.0",
		}, {
			label: "invalid range end",
			input: "0.0.0.0-1-sdfgkjhsdfg",
			ok:    true,
			want:  "0.0.0.0,0.0.0.1",
		}, {
			label: "range and IP",
			input: "127.0.0.1-3,255.0.0.0",
			ok:    true,
			want:  "127.0.0.1,127.0.0.2,127.0.0.3,255.0.0.0",
		}, {
			label: "extraneous comma",
			input: "127.0.0.1-3,255.0.0.0,",
		}, {
			label: "whitespace after comma",
			input: "127.0.0.1-3, 255.0.0.0",
		}, {
			label: "whitespace before comma",
			input: "127.0.0.1-3 ,255.0.0.0",
		}, {
			label: "trailing whitespace",
			input: "127.0.0.1-3,255.0.0.0 ",
		},
	}
	for _, c := range cases {
		f := func(t *testing.T) {
			var ips ParseIPs
			err := ips.Set(c.input)
			if err != nil && c.ok {
				t.Errorf("got %v; want <nil>", err)
			}
			if err == nil && !c.ok {
				t.Error("got <nil>; want some error")
			}
			if err == nil && c.ok {
				got := ips.String()
				if got != c.want {
					t.Errorf("got %q; want %q", got, c.want)
				}
			}
		}
		t.Run(c.label, f)
	}
}

func TestParseIPsSetPanic(t *testing.T) {
	cases := []struct {
		label string
		input string
	}{
		{
			label: "invalid range start",
			input: "foo-3",
		}, {

			label: "leading whitespace",
			input: " 127.0.0.1-3,255.0.0.0",
		},
	}
	for _, c := range cases {
		f := func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Error("expected panic")
				}
			}()
			var ips ParseIPs
			ips.Set(c.input)
		}
		t.Run(c.label, f)
	}
}

func TestNilParseCIDRs(t *testing.T) {
	const want = ""
	got := (*ParseCIDRs)(nil).String()
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestParseCIDRs(t *testing.T) {
	cases := []struct {
		label string
		input string
		ok    bool
		want  string
	}{
		{
			label: "empty",
			input: "",
		}, {
			label: "valid CIDRs",
			input: "192.0.2.1/24,193.0.2.1/16",
			ok:    true,
			want:  "192.0.2.0/24,193.0.0.0/16",
		}, {
			label: "invalid CIDRs",
			input: "192.0.2.1/24,193.0.2.1/66",
		}, {
			label: "whitespace",
			input: "\t192.0.2.1/24, 193.0.2.1/16 ",
		}, {
			label: "extraneous comma",
			input: "192.0.2.1/24,193.0.2.1/16,",
		},
	}
	for _, c := range cases {
		f := func(t *testing.T) {
			var cidrs ParseCIDRs
			err := cidrs.Set(c.input)
			if err != nil && c.ok {
				t.Errorf("got %v; want <nil>", err)
			}
			if err == nil && !c.ok {
				t.Error("got <nil>; want some error")
			}
			if err == nil && c.ok {
				got := cidrs.String()
				if got != c.want {
					t.Errorf("got %q; want %q", got, c.want)
				}
			}
		}
		t.Run(c.label, f)
	}
}
