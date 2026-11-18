//go:build unix

package svyazka

import (
	"os"
	"syscall"
)

func chownLikeDir(path, dir string) {
	if os.Geteuid() != 0 {
		return
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		_ = os.Chown(path, int(st.Uid), int(st.Gid))
	}
}
