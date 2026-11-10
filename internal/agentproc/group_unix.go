//go:build !windows

package agentproc

import (
	"os/exec"
	"syscall"
)

func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminateGroup(cmd *exec.Cmd) {
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}

func killGroup(cmd *exec.Cmd) {
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

// KillGroupByPID stops a leftover process group from an earlier run. Agents
// lead their own group, so a reused pid that leads no group is left alone.
func KillGroupByPID(pid int) {
	if pid <= 1 {
		return
	}
	if pgid, err := syscall.Getpgid(pid); err != nil || pgid != pid {
		return
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
