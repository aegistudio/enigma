package main

import (
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

const (
	RENAME_NOREPLACE = unix.RENAME_NOREPLACE
	O_DIRECT         = syscall.O_DIRECT
)

func fuseFillWithStat(result *fuse.Attr, s *syscall.Stat_t) {
	devMask := uint64(s.Dev)<<32 | uint64(s.Dev)>>32
	result.Ino = devMask ^ s.Ino
	result.Atime = uint64(s.Atim.Sec)
	result.Atimensec = uint32(s.Atim.Nsec)
	result.Mtime = uint64(s.Mtim.Sec)
	result.Mtimensec = uint32(s.Mtim.Nsec)
	result.Ctime = uint64(s.Ctim.Sec)
	result.Ctimensec = uint32(s.Ctim.Nsec)
	result.Nlink = 1
	result.Blksize = uint32(s.Blksize)
	result.Blocks = uint64(s.Blocks)
	result.Uid = uint32(s.Uid)
	result.Gid = uint32(s.Gid)
}
