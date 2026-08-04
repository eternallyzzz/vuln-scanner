//go:build windows

package windows

import (
	"testing"
	"time"
)

func TestCollectorWUATimeout(t *testing.T) {
	c := New()
	if c.wuaTimeout() != 60*time.Second {
		t.Fatalf("default timeout wrong: %v", c.wuaTimeout())
	}
	c.SetWUATimeout(90)
	if c.wuaTimeout() != 90*time.Second {
		t.Fatalf("set timeout wrong: %v", c.wuaTimeout())
	}
	c.SetWUATimeout(0)
	if c.wuaTimeout() != 60*time.Second {
		t.Fatalf("non-positive timeout must keep default, got %v", c.wuaTimeout())
	}
}
