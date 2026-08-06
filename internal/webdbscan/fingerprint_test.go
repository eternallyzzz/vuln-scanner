package webdbscan

import (
	"reflect"
	"testing"
)

func TestFingerprintWeb(t *testing.T) {
	cases := []struct {
		name string
		in   WebFingerprintInput
		want []Product
	}{
		{
			name: "nginx with version",
			in:   WebFingerprintInput{Server: "nginx/1.18.0"},
			want: []Product{{Name: "nginx", Version: "1.18.0", Evidence: "Server: nginx/1.18.0"}},
		},
		{
			name: "openresty maps to nginx",
			in:   WebFingerprintInput{Server: "openresty/1.21.4.1"},
			want: []Product{{Name: "nginx", Version: "1.21.4.1", Evidence: "Server: openresty/1.21.4.1"}},
		},
		{
			name: "apache and php",
			in: WebFingerprintInput{
				Server:     "Apache/2.4.57 (Ubuntu)",
				XPoweredBy: "PHP/8.1.2",
			},
			want: []Product{
				{Name: "apache", Version: "2.4.57", Evidence: "Server: Apache/2.4.57 (Ubuntu)"},
				{Name: "php", Version: "8.1.2", Evidence: "X-Powered-By: PHP/8.1.2"},
			},
		},
		{
			name: "wordpress generator",
			in: WebFingerprintInput{
				MetaGenerator: "WordPress 6.4.2",
			},
			want: []Product{{Name: "wordpress", Version: "6.4.2", Evidence: "Generator: WordPress 6.4.2"}},
		},
		{
			name: "wordpress body hint without version",
			in: WebFingerprintInput{
				Body: `<html><link rel="stylesheet" href="/wp-content/themes/x/style.css"></html>`,
			},
			want: []Product{{Name: "wordpress", Evidence: "body: wp-content/wp-includes"}},
		},
		{
			name: "tomcat coyote",
			in:   WebFingerprintInput{Server: "Apache-Coyote/1.1"},
			want: []Product{{Name: "tomcat", Version: "1.1", Evidence: "Server: Apache-Coyote/1.1"}},
		},
		{
			name: "unknown server",
			in:   WebFingerprintInput{Server: "Custom-Server/9.9"},
			want: nil,
		},
		{
			name: "duplicate product first wins",
			in: WebFingerprintInput{
				Server:        "nginx/1.18.0",
				MetaGenerator: "WordPress 6.4.2",
				Body:          "wp-content",
			},
			want: []Product{
				{Name: "nginx", Version: "1.18.0", Evidence: "Server: nginx/1.18.0"},
				{Name: "wordpress", Version: "6.4.2", Evidence: "Generator: WordPress 6.4.2"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FingerprintWeb(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("FingerprintWeb(%+v) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestExtractTitleAndGenerator(t *testing.T) {
	body := `<html><head><title>  My App &lt;ok&gt;  </title><meta name="generator" content="Hugo 0.123.4"></head></html>`
	if got := extractTitle(body); got != "My App <ok>" {
		t.Fatalf("extractTitle = %q", got)
	}
	if got := extractMetaGenerator(body); got != "Hugo 0.123.4" {
		t.Fatalf("extractMetaGenerator = %q", got)
	}
}
