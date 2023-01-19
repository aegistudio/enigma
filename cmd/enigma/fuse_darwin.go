package main

import (
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
)

const (
	RENAME_NOREPLACE = 0
	O_DIRECT         = 0
)

func fuseFillWithStat(result *fuse.Attr, s *syscall.Stat_t) {
	result.Atime = uint64(s.Atimespec.Sec)
	result.Atimensec = uint32(s.Atimespec.Nsec)
	result.Mtime = uint64(s.Mtimespec.Sec)
	result.Mtimensec = uint32(s.Mtimespec.Nsec)
	result.Ctime = uint64(s.Ctimespec.Sec)
	result.Ctimensec = uint32(s.Ctimespec.Nsec)
	result.Crtime_ = uint64(s.Birthtimespec.Sec)
	result.Crtimensec_ = uint32(s.Birthtimespec.Nsec)
	result.Nlink = 1
	result.Blksize = uint32(s.Blksize)
	result.Blocks = uint64(s.Blocks)
	result.Uid = uint32(s.Uid)
	result.Gid = uint32(s.Gid)
}
