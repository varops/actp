//go:build !windows

package server

import "syscall"

func processAlive(pid int) bool {
	return pid > 1 && syscall.Kill(pid, 0) == nil
}
