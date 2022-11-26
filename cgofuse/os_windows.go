//go:build windows
// +build windows

package cgofuse

import (
	"syscall"
	"time"

	"github.com/winfsp/cgofuse/fuse"
)

// fuseWindows indicates that we are running on windows platform,
// and some special handlings would be enabled here.
const fuseWindows = true

type unixStat struct {
}

func fillUnixStat(sysStat unixStat, stat *fuse.Stat_t) {
}

type win32FileAttr = *syscall.Win32FileAttributeData

func fillWin32FileAttr(sysStat win32FileAttr, stat *fuse.Stat_t) {
	// See also os/types_windows.go of golang standard library.
	creationTime := time.Unix(0, sysStat.CreationTime.Nanoseconds())
	stat.Ctim = fuse.NewTimespec(creationTime)
	lastAccessTime := time.Unix(0, sysStat.LastAccessTime.Nanoseconds())
	stat.Atim = fuse.NewTimespec(lastAccessTime)
	attributes := sysStat.FileAttributes
	if attributes&syscall.FILE_ATTRIBUTE_ARCHIVE != 0 {
		stat.Flags |= fuse.UF_ARCHIVE
	}
	if attributes&syscall.FILE_ATTRIBUTE_READONLY != 0 {
		stat.Flags |= fuse.UF_READONLY
	}
	if attributes&syscall.FILE_ATTRIBUTE_SYSTEM != 0 {
		stat.Flags |= fuse.UF_SYSTEM
	}
	if attributes&syscall.FILE_ATTRIBUTE_HIDDEN != 0 {
		stat.Flags |= fuse.UF_HIDDEN
	}
}

func init() {
	syscallFuseErrorMap[syscall.ERROR_FILE_NOT_FOUND] = fuse.ENOENT
	syscallFuseErrorMap[syscall.ERROR_PATH_NOT_FOUND] = fuse.ENOENT
	syscallFuseErrorMap[syscall.ERROR_ACCESS_DENIED] = fuse.EACCES
	syscallFuseErrorMap[syscall.ERROR_FILE_EXISTS] = fuse.EEXIST
	syscallFuseErrorMap[syscall.ERROR_BROKEN_PIPE] = fuse.EPIPE
	syscallFuseErrorMap[syscall.ERROR_DIR_NOT_EMPTY] = fuse.ENOTEMPTY
	syscallFuseErrorMap[syscall.ERROR_ALREADY_EXISTS] = fuse.EEXIST
}
