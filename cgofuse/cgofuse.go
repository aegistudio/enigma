// Package cgofuse is a wrapper for the enigma file system,
// which is adapted to the winfsp's fuse interface.
package cgofuse

import (
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"github.com/spf13/afero"
	"github.com/winfsp/cgofuse/fuse"

	"github.com/aegistudio/enigma"
)

// syscallFuseErrorMap is the mapping for the OS's local error
// to the error that must be returned by the syscall.
//
// There's no guarantee that the syscall.Errno's minus value is
// the same as fuse's error code, so I make a mapping instead.
var syscallFuseErrorMap = map[syscall.Errno]int{
	syscall.E2BIG:           fuse.E2BIG,
	syscall.EACCES:          fuse.EACCES,
	syscall.EADDRINUSE:      fuse.EADDRINUSE,
	syscall.EADDRNOTAVAIL:   fuse.EADDRNOTAVAIL,
	syscall.EAFNOSUPPORT:    fuse.EAFNOSUPPORT,
	syscall.EAGAIN:          fuse.EAGAIN,
	syscall.EALREADY:        fuse.EALREADY,
	syscall.EBADF:           fuse.EBADF,
	syscall.EBADMSG:         fuse.EBADMSG,
	syscall.EBUSY:           fuse.EBUSY,
	syscall.ECANCELED:       fuse.ECANCELED,
	syscall.ECHILD:          fuse.ECHILD,
	syscall.ECONNABORTED:    fuse.ECONNABORTED,
	syscall.ECONNREFUSED:    fuse.ECONNREFUSED,
	syscall.ECONNRESET:      fuse.ECONNRESET,
	syscall.EDEADLK:         fuse.EDEADLK,
	syscall.EDESTADDRREQ:    fuse.EDESTADDRREQ,
	syscall.EDOM:            fuse.EDOM,
	syscall.EEXIST:          fuse.EEXIST,
	syscall.EFAULT:          fuse.EFAULT,
	syscall.EFBIG:           fuse.EFBIG,
	syscall.EHOSTUNREACH:    fuse.EHOSTUNREACH,
	syscall.EIDRM:           fuse.EIDRM,
	syscall.EILSEQ:          fuse.EILSEQ,
	syscall.EINPROGRESS:     fuse.EINPROGRESS,
	syscall.EINTR:           fuse.EINTR,
	syscall.EINVAL:          fuse.EINVAL,
	syscall.EIO:             fuse.EIO,
	syscall.EISCONN:         fuse.EISCONN,
	syscall.EISDIR:          fuse.EISDIR,
	syscall.ELOOP:           fuse.ELOOP,
	syscall.EMFILE:          fuse.EMFILE,
	syscall.EMLINK:          fuse.EMLINK,
	syscall.EMSGSIZE:        fuse.EMSGSIZE,
	syscall.ENAMETOOLONG:    fuse.ENAMETOOLONG,
	syscall.ENETDOWN:        fuse.ENETDOWN,
	syscall.ENETRESET:       fuse.ENETRESET,
	syscall.ENETUNREACH:     fuse.ENETUNREACH,
	syscall.ENFILE:          fuse.ENFILE,
	syscall.ENOBUFS:         fuse.ENOBUFS,
	syscall.ENODATA:         fuse.ENODATA,
	syscall.ENODEV:          fuse.ENODEV,
	syscall.ENOENT:          fuse.ENOENT,
	syscall.ENOEXEC:         fuse.ENOEXEC,
	syscall.ENOLCK:          fuse.ENOLCK,
	syscall.ENOLINK:         fuse.ENOLINK,
	syscall.ENOMEM:          fuse.ENOMEM,
	syscall.ENOMSG:          fuse.ENOMSG,
	syscall.ENOPROTOOPT:     fuse.ENOPROTOOPT,
	syscall.ENOSPC:          fuse.ENOSPC,
	syscall.ENOSR:           fuse.ENOSR,
	syscall.ENOSTR:          fuse.ENOSTR,
	syscall.ENOSYS:          fuse.ENOSYS,
	syscall.ENOTCONN:        fuse.ENOTCONN,
	syscall.ENOTDIR:         fuse.ENOTDIR,
	syscall.ENOTEMPTY:       fuse.ENOTEMPTY,
	syscall.ENOTRECOVERABLE: fuse.ENOTRECOVERABLE,
	syscall.ENOTSOCK:        fuse.ENOTSOCK,
	syscall.ENOTSUP:         fuse.ENOTSUP,
	syscall.ENOTTY:          fuse.ENOTTY,
	syscall.ENXIO:           fuse.ENXIO,
	syscall.EOPNOTSUPP:      fuse.EOPNOTSUPP,
	syscall.EOVERFLOW:       fuse.EOVERFLOW,
	syscall.EOWNERDEAD:      fuse.EOWNERDEAD,
	syscall.EPERM:           fuse.EPERM,
	syscall.EPIPE:           fuse.EPIPE,
	syscall.EPROTO:          fuse.EPROTO,
	syscall.EPROTONOSUPPORT: fuse.EPROTONOSUPPORT,
	syscall.EPROTOTYPE:      fuse.EPROTOTYPE,
	syscall.ERANGE:          fuse.ERANGE,
	syscall.EROFS:           fuse.EROFS,
	syscall.ESPIPE:          fuse.ESPIPE,
	syscall.ESRCH:           fuse.ESRCH,
	syscall.ETIME:           fuse.ETIME,
	syscall.ETIMEDOUT:       fuse.ETIMEDOUT,
	syscall.ETXTBSY:         fuse.ETXTBSY,
	syscall.EWOULDBLOCK:     fuse.EWOULDBLOCK,
	syscall.EXDEV:           fuse.EXDEV,
}

// fuseNoFile indicates the operation is towards the
// path instead of file.
const fuseNoFile = ^uint64(0)

// Fs is the adapted file system interface for fuse.
type Fs struct {
	fuse.FileSystemBase
	efs *enigma.Fs

	fileMap sync.Map
	dirMap  sync.Map

	// windowsDisposerMap is a special handler for windows
	// opening file with dispose-on-close flag to delete.
	//
	// To dispose, there must be at most one reader (since the
	// system will complain about access error otherwise), and
	// there must be an unlink call to it. The deletion will
	// be at the file's exit if it cannot be remove immediately.
	windowsDisposerMap *sync.Map
}

func New(efs *enigma.Fs) *Fs {
	result := &Fs{efs: efs}
	if fuseWindows {
		result.windowsDisposerMap = &sync.Map{}
	}
	return result
}

func collapseSyscall(err error) int {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if v, ok := syscallFuseErrorMap[errno]; ok {
			return -v
		}
	}
	return -fuse.EINVAL
}

type attr interface {
	destroy(*Fs)
}

type nullAttr struct {
}

func (nullAttr) destroy(*Fs) {
}

type file struct {
	afero.File
	attr
}

type storeMapFunc func(afero.File, error) (int, uint64)

func (fs *Fs) wouldExtendStoreSyncMap(
	m *sync.Map, filter func(os.FileInfo) error,
	wrapper func(afero.File) (attr, error),
) storeMapFunc {
	return func(f afero.File, err error) (int, uint64) {
		defer func() {
			if f != nil {
				_ = f.Close()
			}
		}()
		if err != nil {
			return collapseSyscall(err), fuseNoFile
		}
		stat, err := f.Stat()
		if err != nil {
			return collapseSyscall(err), fuseNoFile
		}
		if err := filter(stat); err != nil {
			return collapseSyscall(err), fuseNoFile
		}
		attr, err := wrapper(f)
		if err != nil {
			return collapseSyscall(err), fuseNoFile
		}
		defer func() {
			if attr != nil {
				attr.destroy(fs)
			}
		}()
		// XXX: we assume that pointers in golang will not move,
		// and we might have to find another way of generating
		// unique ID if golang implements some sweep GC on heap.
		value := &file{
			File: f,
			attr: attr,
		}
		fh := uint64(uintptr(unsafe.Pointer(value)))
		if _, loaded := m.LoadOrStore(fh, value); loaded {
			return -fuse.ENOMEM, fuseNoFile
		}
		f = nil
		attr = nil
		return 0, fh
	}
}

type windowsDisposeState struct {
	name        string
	refCount    uint64
	disposeMark uint64
	removeCh    chan struct{}
}

func (f *windowsDisposeState) markDispose() {
	atomic.StoreUint64(&f.disposeMark, 1)
}

func (f *windowsDisposeState) checkDispose() bool {
	return atomic.LoadUint64(&f.disposeMark) == 1
}

func (f *windowsDisposeState) incrementOpenFile() bool {
	for {
		val := atomic.LoadUint64(&f.refCount)
		if val == 0 {
			<-f.removeCh
			return false
		}
		if atomic.CompareAndSwapUint64(&f.refCount, val, val+1) {
			return true
		}
	}
}

func (f *windowsDisposeState) decrementOpenFile() bool {
	return atomic.AddUint64(&f.refCount, ^uint64(0)) == 0
}

type fileAttr struct {
	isAppend        bool
	windowsReadOnly bool
	disposer        *windowsDisposeState
}

func (f *fileAttr) destroy(fs *Fs) {
	disposer := f.disposer
	if disposer != nil {
		if disposer.decrementOpenFile() {
			fs.windowsDisposerMap.Delete(disposer.name)
			defer close(disposer.removeCh)
			if disposer.checkDispose() {
				_ = fs.efs.Remove(disposer.name)
			}
		}
	}
}

func (fs *Fs) wouldStoreFile(isAppend, windowsReadOnly bool) storeMapFunc {
	return fs.wouldExtendStoreSyncMap(&fs.fileMap, func(
		i os.FileInfo,
	) error {
		if !i.Mode().IsRegular() {
			return syscall.EISDIR
		}
		return nil
	}, func(f afero.File) (attr, error) {
		var disposer *windowsDisposeState
		if windowsReadOnly {
			name := f.Name()
			for {
				current := &windowsDisposeState{
					name:     name,
					refCount: 1,
				}
				if value, ok := fs.windowsDisposerMap.LoadOrStore(name, current); ok {
					if value.(*windowsDisposeState).incrementOpenFile() {
						disposer = current
						break
					}
				} else {
					disposer = current
					break
				}
			}
		}
		return &fileAttr{
			isAppend:        isAppend,
			windowsReadOnly: windowsReadOnly,
			disposer:        disposer,
		}, nil
	})
}

func (fs *Fs) wouldStoreDir() storeMapFunc {
	return fs.wouldExtendStoreSyncMap(&fs.dirMap, func(
		i os.FileInfo,
	) error {
		if !i.IsDir() {
			return syscall.ENOTDIR
		}
		return nil
	}, func(f afero.File) (attr, error) {
		return &nullAttr{}, nil
	})
}

func (fs *Fs) loadSyncMap(m *sync.Map, fh uint64) (*file, bool) {
	f, ok := m.Load(fh)
	if !ok {
		return nil, ok
	}
	return f.(*file), true
}

func (fs *Fs) loadFile(fh uint64) (*file, bool) {
	return fs.loadSyncMap(&fs.fileMap, fh)
}

func (fs *Fs) loadDir(fh uint64) (*file, bool) {
	return fs.loadSyncMap(&fs.dirMap, fh)
}

func (fs *Fs) Chmod(path string, mode uint32) (code int) {
	return collapseSyscall(fs.efs.Chmod(path, os.FileMode(mode).Perm()))
}

func (fs *Fs) Chown(path string, uid, gid uint32) (code int) {
	return collapseSyscall(fs.efs.Chown(path, int(uid), int(gid)))
}

func (fs *Fs) Create(path string, flags int, mode uint32) (int, uint64) {
	return fs.openFile(path, flags|fuse.O_CREAT, mode)
}

func (fs *Fs) destroyFile(f *file) error {
	defer f.attr.destroy(fs)
	return f.Close()
}

func (fs *Fs) Destroy() {
	fs.fileMap.Range(func(key, value interface{}) bool {
		fs.fileMap.Delete(key)
		fs.destroyFile(value.(*file))
		return true
	})
	fs.dirMap.Range(func(key, value interface{}) bool {
		fs.dirMap.Delete(key)
		fs.destroyFile(value.(*file))
		return true
	})
}

func (fs *Fs) Flush(path string, fh uint64) (rerr int) {
	f, ok := fs.loadFile(fh)
	if !ok {
		return collapseSyscall(syscall.EBADF)
	}
	if f.attr.(*fileAttr).windowsReadOnly {
		_ = f.Sync()
		return 0
	}
	return collapseSyscall(f.Sync())
}

func (fs *Fs) Fsync(_ string, datasync bool, fh uint64) int {
	if datasync {
		return collapseSyscall(syscall.ENOSYS)
	}
	f, ok := fs.loadFile(fh)
	if !ok {
		return collapseSyscall(syscall.EBADF)
	}
	return collapseSyscall(f.Sync())
}

func (fs *Fs) Fsyncdir(_ string, datasync bool, fh uint64) int {
	if datasync {
		return collapseSyscall(syscall.ENOSYS)
	}
	f, ok := fs.loadDir(fh)
	if !ok {
		return collapseSyscall(syscall.EBADF)
	}
	return collapseSyscall(f.Sync())
}

func (fs *Fs) Getattr(path string, stat *fuse.Stat_t, fh uint64) (errc int) {
	var info os.FileInfo
	if fh == fuseNoFile {
		n, err := fs.efs.Stat(path)
		if err != nil {
			return collapseSyscall(err)
		}
		info = n
	} else {
		f, ok := fs.loadFile(fh)
		if !ok {
			return collapseSyscall(syscall.EBADF)
		}
		n, err := f.Stat()
		if err != nil {
			return collapseSyscall(err)
		}
		info = n
	}
	uid, gid, _ := fuse.Getcontext()
	stat.Size = info.Size()
	stat.Mode = uint32(info.Mode().Perm())
	if info.IsDir() {
		stat.Mode |= fuse.S_IFDIR
	} else {
		stat.Mode |= fuse.S_IFREG
	}
	stat.Uid = uid
	stat.Gid = gid
	stat.Mtim = fuse.NewTimespec(info.ModTime())
	switch actual := info.Sys().(type) {
	case unixStat:
		fillUnixStat(actual, stat)
	case win32FileAttr:
		fillWin32FileAttr(actual, stat)
	}
	return 0
}

func (fs *Fs) Mkdir(path string, mode uint32) int {
	mkdirMode := os.FileMode(mode).Perm()
	return collapseSyscall(fs.efs.Mkdir(path, mkdirMode))
}

const fuseAllFlags = fuse.O_ACCMODE | fuse.O_APPEND |
	fuse.O_CREAT | fuse.O_EXCL | fuse.O_TRUNC

func (fs *Fs) openFile(
	path string, flags int, mode uint32,
) (code int, fh uint64) {
	if flags&(^fuseAllFlags) != 0 {
		return collapseSyscall(syscall.EINVAL), fuseNoFile
	}

	// Process the flags into os.O_* flags.
	var openFlags int
	if flags&fuse.O_RDONLY != 0 {
		openFlags |= os.O_RDONLY
	}
	if flags&fuse.O_WRONLY != 0 {
		openFlags |= os.O_WRONLY
	}
	if flags&fuse.O_RDWR != 0 {
		openFlags |= os.O_RDWR
	}
	if flags&fuse.O_APPEND != 0 {
		openFlags |= os.O_APPEND
	}
	if flags&fuse.O_CREAT != 0 {
		openFlags |= os.O_CREATE
	}
	if flags&fuse.O_EXCL != 0 {
		openFlags |= os.O_EXCL
	}
	if flags&fuse.O_TRUNC != 0 {
		openFlags |= os.O_TRUNC
	}

	// Ensure this is used for creating a file.
	if (flags&fuse.O_CREAT != 0) && (mode&fuse.S_IFMT != 0) {
		return collapseSyscall(syscall.EINVAL), fuseNoFile
	}

	openMode := os.FileMode(mode).Perm()
	return fs.wouldStoreFile(
		openFlags&os.O_APPEND != 0,
		fuseWindows && (flags&fuse.O_ACCMODE == fuse.O_RDONLY),
	)(fs.efs.OpenFile(path, openFlags, openMode))
}

func (fs *Fs) Open(path string, flags int) (int, uint64) {
	if flags&fuse.O_CREAT != 0 {
		return collapseSyscall(syscall.EINVAL), 0
	}
	return fs.openFile(path, flags, 0)
}

func (fs *Fs) Opendir(path string) (errc int, fh uint64) {
	return fs.wouldStoreDir()(fs.efs.Open(path))
}

func collapseIOError(n int, err error) int {
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		return collapseSyscall(err)
	}
	return n
}

func (fs *Fs) Read(_ string, b []byte, off int64, fh uint64) int {
	f, ok := fs.loadFile(fh)
	if !ok {
		return collapseSyscall(syscall.EBADF)
	}
	return collapseIOError(f.ReadAt(b, off))
}

func (fs *Fs) Readdir(
	path string,
	fill func(name string, stat *fuse.Stat_t, _ int64) bool,
	_ int64, _ uint64,
) int {
	dentries, err := afero.ReadDir(fs.efs, path)
	if err != nil {
		return collapseSyscall(err)
	}
	if !fill(".", nil, 0) {
		return 0
	}
	if !fill("..", nil, 0) {
		return 0
	}
	for _, dentry := range dentries {
		if !fill(dentry.Name(), nil, 0) {
			break
		}
	}
	return 0
}

func (fs *Fs) deleteSyncMap(m *sync.Map, fh uint64) int {
	f, ok := m.Load(fh)
	if !ok {
		return collapseSyscall(syscall.EBADF)
	}
	m.Delete(fh)
	return collapseSyscall(fs.destroyFile(f.(*file)))
}

func (fs *Fs) Release(path string, fh uint64) int {
	return fs.deleteSyncMap(&fs.fileMap, fh)
}

func (fs *Fs) Releasedir(path string, fh uint64) int {
	return fs.deleteSyncMap(&fs.dirMap, fh)
}

func (fs *Fs) Rename(oldpath, newpath string) int {
	return collapseSyscall(fs.efs.Rename(oldpath, newpath))
}

func (fs *Fs) Rmdir(oldpath string) int {
	return collapseSyscall(fs.efs.Remove(oldpath))
}

func (fs *Fs) Statfs(_ string, stat *fuse.Statfs_t) int {
	// XXX: since the afero's interface does not provide the
	// functionalities for stating file system, we mock up
	// some values to make the system works.
	stat.Bsize = 4096
	stat.Frsize = 4096
	stat.Blocks = 1 << 31
	stat.Bfree = 1 << 31
	stat.Bavail = 1 << 31
	stat.Files = 1 << 31
	stat.Ffree = 1 << 31
	stat.Favail = 1 << 31
	stat.Namemax = 4096 // Some big enough dummy value
	return 0
}

func (fs *Fs) Truncate(path string, size int64, fh uint64) int {
	var file afero.File
	if fh != fuseNoFile {
		f, ok := fs.loadFile(fh)
		if !ok {
			return collapseSyscall(syscall.EBADF)
		}
		file = f.File
	} else {
		f, err := fs.efs.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return collapseSyscall(err)
		}
		defer func() { _ = f.Close() }()
		file = f
	}
	return collapseSyscall(file.Truncate(size))
}

func (fs *Fs) Unlink(oldpath string) int {
	if fuseWindows {
		cleanPath := enigma.CleanPath(oldpath)
		if v, ok := fs.windowsDisposerMap.Load(cleanPath); ok {
			v.(*windowsDisposeState).markDispose()
		}
	}
	return collapseSyscall(fs.efs.Remove(oldpath))
}

func (fs *Fs) Write(_ string, b []byte, off int64, fh uint64) int {
	f, ok := fs.loadFile(fh)
	if !ok {
		return collapseSyscall(syscall.EBADF)
	}
	writeFunc := f.Write
	if !f.attr.(*fileAttr).isAppend {
		writeFunc = func(b []byte) (int, error) {
			return f.WriteAt(b, off)
		}
	}
	return collapseIOError(writeFunc(b))
}

func (fs *Fs) Utimens(path string, tmsp []fuse.Timespec) int {
	atime, mtime := tmsp[0].Time(), tmsp[1].Time()
	return collapseSyscall(fs.efs.Chtimes(path, atime, mtime))
}
