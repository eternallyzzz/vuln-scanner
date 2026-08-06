package webdbscan

import "testing"

func TestNormalizeWebTarget(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"10.0.0.1", "http://10.0.0.1", false},
		{"10.0.0.1:8080", "http://10.0.0.1:8080", false},
		{"https://app.example.com:8443/admin", "https://app.example.com:8443/admin", false},
		{"http://host/path", "http://host/path", false},
		{"[::1]:8080", "http://[::1]:8080", false},
		{"", "", true},
		{"a b", "", true},
		{"ftp://host", "", true},
		{"http://", "", true},
		{"http://user:pass@host", "", true},
		{"http://host:70000", "", true},
		{"http://host:abc", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeWebTarget(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeWebTarget(%q) should fail, got %q", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("NormalizeWebTarget(%q) = (%q, %v), want %q", c.in, got, err, c.want)
		}
	}
}

func TestNormalizeDBTarget(t *testing.T) {
	cases := []struct {
		in      string
		dbType  string
		want    string
		wantErr bool
	}{
		{"10.0.0.1", "mysql", "10.0.0.1:3306", false},
		{"10.0.0.1:3307", "mysql", "10.0.0.1:3307", false},
		{"db.example.com", "postgresql", "db.example.com:5432", false},
		{"10.0.0.1:6380", "redis", "10.0.0.1:6380", false},
		{"[::1]:5432", "postgresql", "[::1]:5432", false},
		{"", "mysql", "", true},
		{"a b", "mysql", "", true},
		{"10.0.0.1:70000", "mysql", "", true},
		{"10.0.0.1:abc", "mysql", "", true},
		{"2001:db8::1", "mysql", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeDBTarget(c.in, c.dbType)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeDBTarget(%q,%q) should fail, got %q", c.in, c.dbType, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("NormalizeDBTarget(%q,%q) = (%q, %v), want %q", c.in, c.dbType, got, err, c.want)
		}
	}
}

func TestValidDBTypes(t *testing.T) {
	for _, db := range ValidDBTypes() {
		if !IsValidDBType(db) {
			t.Fatalf("IsValidDBType(%q) = false", db)
		}
	}
	for _, db := range []string{"mssql", "mongodb", "oracle", ""} {
		if IsValidDBType(db) {
			t.Fatalf("IsValidDBType(%q) = true, want false", db)
		}
	}
}
