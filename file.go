package hologram

import (
	"crypto/cipher"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/afero"
)

// fileInfo delegates and replace the name of the file.
type fileInfo struct {
	name string
	info os.FileInfo
}

func (f *fileInfo) Name() string       { return f.name }
func (f *fileInfo) Size() int64        { return f.info.Size() }
func (f *fileInfo) Mode() os.FileMode  { return f.info.Mode() }
func (f *fileInfo) ModTime() time.Time { return f.info.ModTime() }
func (f *fileInfo) IsDir() bool        { return f.info.IsDir() }

// Sys returns syscall.Stat_t on linux and darwin, and
// syscall.Win32FileAttributeData on windows, none of these
// exposes the real filename info so I think it is okay.
//
// Self implemented filesystems might expose this info but
// it is okay to ignore those cases.
func (f *fileInfo) Sys() interface{} { return f.info.Sys() }

// fileBase is the base of the file operations.
type fileBase struct {
	name  string
	inner afero.File
}

func (f *fileBase) cleansePathError(err error) error {
	return cleansePathError(f.name, err)
}

func (f *fileBase) pathError(op string, err error) error {
	return pathError(op, f.name, err)
}

func (f *fileBase) Close() error {
	return f.cleansePathError(f.inner.Close())
}

func (f *fileBase) Readdir(int) ([]os.FileInfo, error) {
	return nil, f.pathError("readdirent", syscall.EINVAL)
}

func (f *fileBase) Readdirnames(int) ([]string, error) {
	// See also the bug comment on os/dir.go, which requires
	// to return []string{} instead of nil in this case.
	return []string{}, f.pathError("readdirent", syscall.EINVAL)
}

func (f *fileBase) Name() string {
	return f.name
}

func (f *fileBase) Stat() (os.FileInfo, error) {
	info, err := f.inner.Stat()
	if err != nil {
		return info, f.cleansePathError(err)
	}
	name := filepath.Base(f.name)
	return &fileInfo{name: name, info: info}, nil
}

func (f *fileBase) Sync() error {
	return f.cleansePathError(f.inner.Sync())
}

// fileInfoSlice is used for sorting directory entries.
type fileInfoSlice struct {
	v []os.FileInfo
}

func (f *fileInfoSlice) Len() int {
	return len(f.v)
}

func (f *fileInfoSlice) Less(i, j int) bool {
	return f.v[i].Name() < f.v[j].Name()
}

func (f *fileInfoSlice) Swap(i, j int) {
	f.v[i], f.v[j] = f.v[j], f.v[i]
}

// dir implements the directory file, which only supports
// directory related operations.
//
// Since the order of encrypted file names are very likely
// to be different from the plain text one, and golang
// requires the directory entries read to be lexically
// ordered, we requires that
type dir struct {
	*fileBase
	config *Config
	block  cipher.Block
	nonce  nonceType
	once   sync.Once
	mtx    sync.Mutex
	err    error
	stats  []os.FileInfo
	names  []string
}

func (d *dir) Read([]byte) (int, error) {
	return 0, d.pathError("read", syscall.EINVAL)
}

func (d *dir) ReadAt([]byte, int64) (int, error) {
	return 0, d.pathError("read", syscall.EINVAL)
}

func (d *dir) Seek(int64, int) (int64, error) {
	return 0, d.pathError("seek", syscall.EINVAL)
}

func (d *dir) Write([]byte) (int, error) {
	return 0, d.pathError("write", syscall.EINVAL)
}

func (d *dir) WriteAt([]byte, int64) (int, error) {
	return 0, d.pathError("write", syscall.EINVAL)
}

func (d *dir) Readdir(count int) ([]os.FileInfo, error) {
	// Read all dirents at once since their order can only be
	// determined after all of them are read.
	d.once.Do(func() {
		stats, err := d.inner.Readdir(-1)
		if err != nil {
			d.err = d.cleansePathError(err)
			return
		}

		// Filter the stat blocks and reform them here.
		var realStats []os.FileInfo
		for _, stat := range stats {
			realName := d.nonce.decryptName(
				d.config, d.block, []byte(stat.Name()))
			if realName == "" {
				continue
			}
			realStats = append(realStats, &fileInfo{
				name: realName,
				info: stat,
			})
		}

		// Sort the slice and collect the result here.
		sort.Sort(&fileInfoSlice{v: realStats})
		d.stats = realStats
	})

	// Copy the data out here. Since operations here are just
	// tiny and non-blocking, it won't become bottleneck.
	d.mtx.Lock()
	defer d.mtx.Unlock()
	var result []os.FileInfo
	if count <= 0 || count >= len(d.stats) {
		result = d.stats
		d.stats = nil
	} else {
		result = d.stats[:count]
		d.stats = d.stats[count:]
	}
	if result == nil {
		return nil, d.err
	}
	return result, nil
}

func (d *dir) Readdirnames(count int) ([]string, error) {
	// Read all directory entry names here at once since their
	// order can only be determined after all of them are read.
	d.once.Do(func() {
		names, err := d.inner.Readdirnames(-1)
		if err != nil {
			d.err = d.cleansePathError(err)
			return
		}

		// Filter the file names and reform them here.
		var realNames []string
		for _, name := range names {
			realName := d.nonce.decryptName(
				d.config, d.block, []byte(name))
			if realName == "" {
				continue
			}
			realNames = append(realNames, realName)
		}

		// Sort the slice and collect the result here.
		sort.Strings(realNames)
		d.names = realNames
	})

	// Copy the data out here. Since operations here are just
	// tiny and non-blocking, it won't become bottleneck.
	d.mtx.Lock()
	defer d.mtx.Unlock()
	var result []string
	if count <= 0 || count >= len(d.names) {
		result = d.names
		d.names = nil
	} else {
		result = d.names[:count]
		d.names = d.names[count:]
	}
	if result == nil {
		return []string{}, d.err
	}
	return result, nil
}

func (d *dir) Truncate(int64) error {
	return d.pathError("truncate", syscall.EINVAL)
}

func (d *dir) WriteString(s string) (int, error) {
	return 0, d.pathError("write", syscall.EINVAL)
}

// readOnlyFile is the file that is open in read only mode.
//
// Since opening in this mode will not update the file state,
// it is okay when we do not synchronize the file status.
type readOnlyFile struct {
	*fileBase
	mtx sync.Mutex
	ctr *randCTR
}

func (f *readOnlyFile) Read(b []byte) (int, error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	n, err := f.inner.Read(b)
	if n > 0 {
		f.ctr.XORKeyStream(b[:n], b[:n])
	}
	return n, f.cleansePathError(err)
}

func (f *readOnlyFile) ReadAt(b []byte, off int64) (int, error) {
	n, err := f.inner.ReadAt(b, off)
	if n > 0 {
		ctr := f.ctr.recreate()
		ctr.Seek(uint64(off))
		ctr.XORKeyStream(b[:n], b[:n])
	}
	return n, f.cleansePathError(err)
}

func (f *readOnlyFile) Seek(offset int64, whence int) (int64, error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	off, err := f.inner.Seek(offset, whence)
	if err == nil {
		f.ctr.Seek(uint64(off))
	}
	return off, f.cleansePathError(err)
}

func (f *readOnlyFile) Write(b []byte) (int, error) {
	return 0, f.pathError("write", syscall.EPERM)
}

func (f *readOnlyFile) WriteAt(b []byte, off int64) (int, error) {
	return 0, f.pathError("write", syscall.EPERM)
}

func (f *readOnlyFile) Truncate(size int64) error {
	return f.pathError("truncate", syscall.EPERM)
}

func (f *readOnlyFile) WriteString(s string) (int, error) {
	return 0, f.pathError("write", syscall.EPERM)
}

// fileSyncMap is the map for synchronizing open files in
// writable mode. The entries might also be evicted if their
// underlying dentries are removed through Fs.Remove.
type fileSyncMap struct {
	mtx sync.Mutex
	m   map[string]*fileSyncBlock
}

// getLocked is the locked version of get.
func (fm *fileSyncMap) getLocked(
	name string, size uint64,
) *fileSyncBlock {
	if b, ok := fm.m[name]; ok {
		b.refCount++
		return b
	}
	promiseCh := make(chan struct{})
	close(promiseCh)
	b := &fileSyncBlock{
		refCount:    1,
		size:        size,
		promiseCh:   promiseCh,
		promiseSize: size,
	}
	fm.m[name] = b
	return b
}

// get creates or retrieve a new sync block from the map.
func (fm *fileSyncMap) get(name string, size uint64) *fileSyncBlock {
	fm.mtx.Lock()
	defer fm.mtx.Unlock()
	return fm.getLocked(name, size)
}

// evictLocked attempts to remove entries from the sync map.
//
// Mutex must be held before invoking the function, and the
// sync block will be removed from the sync map directly.
// Further operations will not affect the block inside.
func (fm *fileSyncMap) evictLocked(name string) {
	if entry, ok := fm.m[name]; ok {
		// XXX: we add a phantom counter so that it will
		// not affect the entry in the map after all the
		// readers has discarded them.
		entry.refCount++
		delete(fm.m, name)
	}
}

// putLocked is the locked version of put.
func (fm *fileSyncMap) putLocked(name string, b *fileSyncBlock) {
	b.refCount--
	if b.refCount == 0 {
		delete(fm.m, name)
	}
}

// put decrease the reference counter of specified dentry,
// and remove that entry if all of them goes down to zero.
//
// The closed file holding those entries are just fine because
// they will not able to modify that files anymore.
func (fm *fileSyncMap) put(name string, b *fileSyncBlock) {
	fm.mtx.Lock()
	defer fm.mtx.Unlock()
	fm.putLocked(name, b)
}

// fileSyncMapRack is a collection of file's sync map where
// we create multiple instances of them to reduce collision.
type fileSyncMapRack struct {
	ms [32]*fileSyncMap
}

func newFileSyncMapRack() *fileSyncMapRack {
	result := &fileSyncMapRack{}
	for i := 0; i < 32; i++ {
		result.ms[i] = &fileSyncMap{
			m: make(map[string]*fileSyncBlock),
		}
	}
	return result
}

func (r *fileSyncMapRack) get(nonce nonceType) *fileSyncMap {
	return r.ms[int(uint8(nonce[0]))&31]
}

// fileSyncBlock is the block that controls the behaviour
// among multiple file at the same path managed by hologram.
//
// Special care must be taken when playing with file boundary,
// that is, writing to the boundary of the file.
//
// Normally speaking, it is really rare to shrink the file's
// size while running, compared to extending the file. So read
// locks when we are extending the file or writing to file's
// internal region, while write locks when we are shrinking.
//
// Furthermore, for those who are expanding the file's boundary,
// they must also be linearized. That is, each such operations
// will be allocated an expected offset after their previous
// operations are done.
type fileSyncBlock struct {
	sync.RWMutex
	refCount    uint64
	size        uint64
	chainMtx    sync.Mutex
	promiseSize uint64
	promiseCh   chan struct{}
}

func (f *fileSyncBlock) getSize() uint64 {
	return atomic.LoadUint64(&f.size)
}

func (f *fileSyncBlock) setSize(s uint64) {
	atomic.StoreUint64(&f.size, s)
}

type filePromise struct {
	block  *fileSyncBlock
	size   uint64
	waitCh chan struct{}
	doneCh chan struct{}
}

func (f *fileSyncBlock) makePromiseLocked(newSize uint64) *filePromise {
	promiseSize := f.promiseSize
	waitCh := f.promiseCh
	doneCh := make(chan struct{})
	f.promiseCh = doneCh
	f.promiseSize = newSize
	return &filePromise{
		block:  f,
		size:   promiseSize,
		waitCh: waitCh,
		doneCh: doneCh,
	}
}

// promiseWhenExpand tries to make promise whenever the caller
// feels like it will expand across the boundaries. Nil will be
// returned whenever it does not rely on such promise.
func (f *fileSyncBlock) promiseWhenExpand(bound uint64) *filePromise {
	if f.getSize() > bound {
		return nil
	}
	f.chainMtx.Lock()
	defer f.chainMtx.Unlock()
	return f.makePromiseLocked(bound)
}

func (f *fileSyncBlock) promiseAppend(size uint64) *filePromise {
	f.chainMtx.Lock()
	defer f.chainMtx.Unlock()
	return f.makePromiseLocked(f.promiseSize + size)
}

// wait for the previous operation to be done and checks whether
// the promise of the size has broken.
func (p *filePromise) wait() bool {
	<-p.waitCh
	realSize := p.block.getSize()
	result := p.size == realSize
	p.size = realSize
	return result
}

// getSize retrieves the promised size.
func (p *filePromise) getSize() uint64 {
	return p.size
}

// setSize sets the real size after this operation.
func (p *filePromise) setSize(realSize uint64) {
	p.size = realSize
}

// done writes back the actual size of data written.
func (p *filePromise) done() {
	p.block.setSize(p.size)
	close(p.doneCh)
}

// writeFileBase is the base of all writable file.
type writeFileBase struct {
	*readOnlyFile
	sync    *fileSyncBlock
	syncMap *fileSyncMap
}

func (f *writeFileBase) Close() error {
	if err := func() error {
		f.sync.RLock()
		defer f.sync.RUnlock()
		return f.readOnlyFile.Close()
	}(); err != nil {
		return err
	}
	f.syncMap.put(f.name, f.sync)
	return nil
}

// truncateLocked is the common helper for truncating file to
// a smaller size. The write lock of the sync block must be
// held before invoking this function.
func (f *writeFileBase) truncateLocked(size int64) error {
	// Shrink the size of the file, the size might be
	// either the set size or the one retrieved by stat.
	err := f.inner.Truncate(size)
	if err == nil {
		f.sync.setSize(uint64(size))
	} else if err != nil &&
		!errors.Is(err, afero.ErrFileClosed) &&
		!errors.Is(err, os.ErrInvalid) &&
		!errors.Is(err, os.ErrClosed) {
		// The file state will become inconsistent when
		// this case happens, so we will just panic to
		// indicate there's an unrecoverable error.
		//
		// The file is ensured to be open when it enter
		// this branch, since we must read lock sync
		// block in order to close it.
		stat, statErr := f.inner.Stat()
		if statErr != nil {
			panic(statErr)
		}
		f.sync.setSize(uint64(stat.Size()))
	}
	return f.cleansePathError(err)
}

// readWriteFile is the type of file that supports both read
// and write, and the file offset affects both operations.
type readWriteFile struct {
	*writeFileBase
}

func (f *readWriteFile) writeCTRLocked(
	b []byte, ctr *randCTR, writeFn func([]byte) (int, error),
) (int, error) {
	// Attempt to acquire the promise block, which indicates the
	// true file size and indicates our behaviour of writing.
	dataOffset := ctr.Tell()
	zeroCursor := uint64(0)
	dataWritten := uint64(0)
	promise := f.sync.promiseWhenExpand(dataOffset + uint64(len(b)))
	waited := false
	if promise != nil {
		zeroCursor = promise.getSize()
		defer func() {
			if !waited {
				_ = promise.wait()
			}
			if zeroCursor > promise.getSize() {
				promise.setSize(zeroCursor)
			}
			if dataWritten > 0 {
				dataCursor := dataOffset + dataWritten
				if dataCursor > promise.getSize() {
					promise.setSize(dataCursor)
				}
			}
			promise.done()
		}()
	} else {
		zeroCursor = dataOffset
	}

	// Encrypt the zeroes before the final cursor, they
	// will be filled before we are writing to the cursor.
	var zeroes []byte
	if promise != nil && zeroCursor < dataOffset {
		zeroes = make([]byte, int(dataOffset-zeroCursor))
		zeroesCTR := ctr.recreate()
		zeroesCTR.Seek(zeroCursor)
		zeroesCTR.XORKeyStream(zeroes, zeroes)
	}

	// Encrypts the data to write using the cipher.
	dst := make([]byte, len(b))
	ctr.XORKeyStream(dst, b)
	defer func() {
		if dataWritten < uint64(len(b)) {
			ctr.Seek(dataOffset + dataWritten)
		}
	}()

	// Wait for other operations to be done, and check whether
	// we must increment the paddings now.
	predictFailed := false
	if promise != nil {
		status := promise.wait()
		waited = true
		if !status {
			predictFailed = true
		}
	}
	if predictFailed {
		zeroCursor = promise.getSize()
		available := zeroCursor + uint64(len(zeroes))
		if available < dataOffset {
			extraZeroesCTR := ctr.recreate()
			extraZeroesCTR.Seek(zeroCursor)
			extraZeroes := make([]byte, int(dataOffset-available))
			extraZeroesCTR.XORKeyStream(extraZeroes[:], extraZeroes[:])
			zeroes = append(extraZeroes, zeroes...)
		}
	}

	// Write out the zero paddings before write offset.
	if zeroCursor < dataOffset {
		zeroes = zeroes[int(dataOffset-zeroCursor):]
		n, err := f.inner.WriteAt(zeroes, int64(zeroCursor))
		zeroCursor += uint64(n)
		if err != nil {
			return 0, f.cleansePathError(err)
		}
	}

	// Write out our data finally.
	n, err := writeFn(dst)
	dataWritten = uint64(n)
	return n, f.cleansePathError(err)
}

func (f *readWriteFile) writeCTR(
	b []byte, ctr *randCTR, writeFn func([]byte) (int, error),
) (int, error) {
	f.sync.RLock()
	defer f.sync.RUnlock()
	return f.writeCTRLocked(b, ctr, writeFn)
}

func (f *readWriteFile) Write(b []byte) (int, error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	return f.writeCTR(b, f.ctr, f.inner.Write)
}

func (f *readWriteFile) WriteAt(b []byte, off int64) (int, error) {
	ctr := f.ctr.recreate()
	ctr.Seek(uint64(off))
	return f.writeCTR(b, ctr, func(b []byte) (int, error) {
		return f.inner.WriteAt(b, off)
	})
}

func (f *readWriteFile) Truncate(size int64) error {
	f.sync.Lock()
	defer f.sync.Unlock()
	oldSize := f.sync.getSize()
	if oldSize < uint64(size) {
		// Fill the padding zeros with our CTR write function.
		ctr := f.ctr.recreate()
		ctr.Seek(uint64(size))
		_, err := f.writeCTRLocked(nil, ctr, func(b []byte) (int, error) {
			return 0, nil
		})
		return err
	} else {
		return f.truncateLocked(size)
	}
}

func (f *readWriteFile) WriteString(s string) (int, error) {
	return f.Write([]byte(s))
}

// appendFile is the type of file that supports writing to
// the end of file only. The file offset affects reading.
type appendFile struct {
	*writeFileBase
}

func (f *appendFile) appendLocked(b []byte) (int, error) {
	// Attempt to acquire the promise block, which indicates the
	// true file size and indicates our behaviour of writing.
	promise := f.sync.promiseAppend(uint64(len(b)))
	numWritten := uint64(0)
	waited := false
	defer func() {
		if !waited {
			_ = promise.wait()
		}
		promise.setSize(promise.getSize() + numWritten)
		promise.done()
	}()

	// Encrypts the data to write using the cipher.
	dst := make([]byte, len(b))
	ctr := f.ctr.recreate()
	ctr.Seek(promise.getSize())
	ctr.XORKeyStream(dst, b)

	// Wait for previous jobs to be done before proceeding on.
	status := promise.wait()
	waited = true

	// Reencrypt the data if the promise has been broken.
	if !status {
		ctr.Seek(promise.getSize())
		ctr.XORKeyStream(dst, b)
	}

	// Write out our data finally.
	n, err := f.inner.Write(dst)
	numWritten += uint64(n)
	return n, f.cleansePathError(err)
}

func (f *appendFile) Write(b []byte) (int, error) {
	f.sync.RLock()
	defer f.sync.RUnlock()
	return f.appendLocked(b)
}

func (f *appendFile) WriteAt([]byte, int64) (int, error) {
	// Append file does not support write at operation.
	return 0, f.pathError("write_at", syscall.EINVAL)
}

func (f *appendFile) Truncate(size int64) error {
	f.sync.Lock()
	defer f.sync.Unlock()
	oldSize := f.sync.getSize()
	if oldSize < uint64(size) {
		// Append the zero data to the tail of the file,
		// by just appending them.
		b := make([]byte, int(uint64(size)-oldSize))
		_, err := f.appendLocked(b)
		return err
	} else {
		return f.truncateLocked(size)
	}
}

func (f *appendFile) WriteString(s string) (int, error) {
	return f.Write([]byte(s))
}

type fileMode int

const (
	fileModeRegular = fileMode(iota)
	fileModeDir
	fileModeOther
)

func convertFileMode(mode os.FileMode) fileMode {
	if mode.IsDir() {
		return fileModeDir
	}
	if mode.IsRegular() {
		return fileModeRegular
	}
	return fileModeOther
}

func (hfs *Fs) OpenFile(
	name string, flag int, perm os.FileMode,
) (afero.File, error) {
	name = cleanPath(name)
	value := hfs.evaluateCacheValue(name)
	nonce := value.nonce
	realPath := filepath.Join(hfs.prefix, value.prefix)
	base := &fileBase{
		name: name,
	}

	// Fast path for opening for read, which required no
	// synchronization. Golang should really make the os
	// flags for os.O_RDONLY, os.O_WRONLY and os.O_RDWR
	// constant values (0, 1 and 2), but it is safe for
	// us now since linux, windows and darwin holds.
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC) == 0 {
		f, err := hfs.inner.OpenFile(realPath, flag, perm)
		if err != nil {
			return nil, cleansePathError(name, err)
		}
		defer func() {
			if f != nil {
				_ = f.Close()
			}
		}()
		stat, err := f.Stat()
		if err != nil {
			return nil, cleansePathError(name, err)
		}
		mode := stat.Mode()
		switch convertFileMode(mode) {
		case fileModeDir:
			base.inner = f
			f = nil
			return &dir{
				fileBase: base,
				config:   hfs.config,
				block:    hfs.block,
				nonce:    nonce,
			}, nil
		case fileModeRegular:
			base.inner = f
			f = nil
			return &readOnlyFile{
				fileBase: base,
				ctr:      newRandCTR(hfs.block, nonce[16:]),
			}, nil
		default:
			return nil, errors.Errorf("unsupported file type %q", mode)
		}
	}

	// The file will be open for read, so we ensure that
	// we are operating on writable file system.
	if !hfs.readWrite {
		return nil, pathError("open", name, syscall.EROFS)
	}
	fsyncMap := hfs.rack.get(nonce)
	fsyncMapLocked := false
	notifyLockedTrunc := false

	// If there has been already some writers, we synchronize
	// the write operations with them, and notify them with
	// the new truncated size.
	//
	// If there has been no writer yet, in order to make our
	// size result valid, we still prevent concurrent creation
	// by locking the synchronize map.
	if flag&os.O_TRUNC != 0 {
		if !fsyncMapLocked {
			fsyncMap.mtx.Lock()
			defer fsyncMap.mtx.Unlock()
			fsyncMapLocked = true
		}
		if b, ok := fsyncMap.m[name]; ok {
			// Wait until we are able to write to the file.
			b.Lock()
			defer b.Unlock()
			notifyLockedTrunc = true
		}
	}

	// Open the file for now to retrieve the file.
	f, err := hfs.inner.OpenFile(realPath, flag, perm)
	if err != nil {
		return nil, cleansePathError(name, err)
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()
	stat, err := f.Stat()
	if err != nil {
		return nil, cleansePathError(name, err)
	}
	size := uint64(stat.Size())
	mode := stat.Mode()
	switch convertFileMode(mode) {
	case fileModeDir:
		// Normally this path should fail, but some file
		// system might still permit opening directories
		// with write flag, so I will still notify them
		// with such flag here.
		base.inner = f
		f = nil
		return &dir{
			fileBase: base,
			config:   hfs.config,
			block:    hfs.block,
			nonce:    nonce,
		}, nil
	case fileModeRegular:
		randCTR := newRandCTR(hfs.block, nonce[16:])
		var fsyncBlock *fileSyncBlock
		if fsyncMapLocked {
			fsyncBlock = fsyncMap.getLocked(name, size)
		} else {
			fsyncBlock = fsyncMap.get(name, size)
		}
		if notifyLockedTrunc {
			fsyncBlock.setSize(size)
			fsyncBlock.promiseSize = size
		}
		base.inner = f
		f = nil
		writeBase := &writeFileBase{
			readOnlyFile: &readOnlyFile{
				fileBase: base,
				ctr:      randCTR,
			},
			sync:    fsyncBlock,
			syncMap: fsyncMap,
		}
		if flag&os.O_APPEND != 0 {
			return &appendFile{writeFileBase: writeBase}, nil
		} else {
			return &readWriteFile{writeFileBase: writeBase}, nil
		}
	default:
		return nil, errors.Errorf("unsupported file type %q", mode)
	}
}

func (hfs *Fs) Remove(name string) error {
	if !hfs.readWrite {
		return pathError("remove", name, syscall.EROFS)
	}
	name = cleanPath(name)
	value := hfs.evaluateCacheValue(name)
	nonce := value.nonce
	realPath := filepath.Join(hfs.prefix, value.prefix)
	fsyncMap := hfs.rack.get(nonce)
	fsyncMap.mtx.Lock()
	defer fsyncMap.mtx.Unlock()
	if err := hfs.inner.Remove(realPath); err != nil {
		return cleansePathError(name, err)
	}
	fsyncMap.evictLocked(name)
	return nil
}
