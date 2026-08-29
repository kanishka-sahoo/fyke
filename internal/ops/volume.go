package ops

import (
	"fmt"
	"os"
	"strconv"
)

func InitVolumes(paths []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("volume initialization must run as root")
	}
	uid, err := strconv.Atoi(os.Getenv("FYKE_RUN_UID"))
	if err != nil || uid < 1 {
		return fmt.Errorf("FYKE_RUN_UID must be a positive numeric user ID")
	}
	gid, err := strconv.Atoi(os.Getenv("FYKE_RUN_GID"))
	if err != nil || gid < 1 {
		return fmt.Errorf("FYKE_RUN_GID must be a positive numeric group ID")
	}
	for _, p := range paths {
		if p == "" || p == "/" {
			return fmt.Errorf("unsafe volume path")
		}
		if e := os.MkdirAll(p, 0700); e != nil {
			return e
		}
		if e := os.Chown(p, uid, gid); e != nil {
			return e
		}
		if e := os.Chmod(p, 0700); e != nil {
			return e
		}
	}
	return nil
}
