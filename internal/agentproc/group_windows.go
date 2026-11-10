//go:build windows

package agentproc

import (
	"os/exec"
	"strconv"
	"syscall"
)

func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
}

// npm-installed agents are .cmd shims; only killing the tree stops the real agent.
func terminateGroup(cmd *exec.Cmd) {
	_ = exec.Command("taskkill", "/T", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
}

func killGroup(cmd *exec.Cmd) {
	_ = exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
}

// KillGroupByPID stops a leftover process tree from an earlier run.
func KillGroupByPID(pid int) {
	if pid > 0 {
		_ = exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(pid)).Run()
	}
}
