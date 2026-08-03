//go:build !linux && !windows

package main

import "fmt"

func installService() error {
	return fmt.Errorf("service installation not supported on this platform")
}

func uninstallService() error {
	return fmt.Errorf("service uninstallation not supported on this platform")
}
