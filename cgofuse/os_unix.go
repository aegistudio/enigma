//go:build !windows
// +build !windows

package cgofuse

import (
	"syscall"
	"time"

	"github.com/winfsp/cgofuse/fuse"
)

const fuseWindows = false

type unixStat = *syscall.Stat_t

func fillUnixStat(sysStat unixStat, stat *fuse.Stat_t) {
	stat.Dev = sysStat.Dev
	stat.Ino = sysStat.Ino
	stat.Nlink = sysStat.Nlink
	stat.Mode = sysStat.Mode
	stat.Uid = sysStat.Uid
	stat.Gid = sysStat.Gid
	stat.Rdev = sysStat.Rdev
	// Size has already been filled
	stat.Atim = fuse.NewTimespec(time.Unix(sysStat.Atim.Unix()))
	// Mtim has already been filled
	stat.Ctim = fuse.NewTimespec(time.Unix(sysStat.Ctim.Unix()))
	stat.Blksize = sysStat.Blksize
	stat.Blocks = sysStat.Blocks
}

type win32FileAttr struct {
}

func fillWin32FileAttr(sysStat win32FileAttr, stat *fuse.Stat_t) {
}
