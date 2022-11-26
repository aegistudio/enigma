package enigma

import (
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
	"github.com/spf13/afero"
	protobuf "google.golang.org/protobuf/proto"

	proto "github.com/aegistudio/enigma/proto"
)

// Config is the backward compatible filesystem config.
type Config = proto.Config

const (
	// CurrentVersion is the version of filesystem config.
	//
	// This field should be increment by one every time we
	// modify the layout of protobuf. The field is also used
	// to detect whether we support the specified filesystem.
	CurrentVersion = 1

	// subcipherName is the name of the subcipher's file.
	subcipherName = ".enigma"

	// writerName is the name of the write locker's file.
	writerName = ".writer"
)

// validateNormalizeConfig is the function trying to check
// whether the config is valid and normalize the config by
// filling the default fields inside (for those from older
// versions).
func validateNormalizeConfig(config *Config) error {
	if config.Version > CurrentVersion {
		return errors.New("current engine is too old")
	}
	if len(config.Key) != 32 {
		return errors.New("key unspecified in config")
	}
	if config.PrefixLength < 1 {
		config.PrefixLength = 1
	}
	if config.PrefixLength > 8 {
		config.PrefixLength = 8
	}
	return nil
}

// Init initializes the root filesystem under the path,
// marking current directory as the root.
//
// The specified directory must exist, and there's no
// current pre-existing subcipher under the path.
func Init(
	inner afero.Fs, rootKey cipher.AEAD, path string,
	userConfig Config,
) error {
	stat, err := inner.Stat(path)
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		// XXX: I've checked GOOS=linux, windows and darwin
		// and ensured they have such a ENOTDIR error.
		return &fs.PathError{
			Op:   "open",
			Path: path,
			Err:  syscall.ENOTDIR,
		}
	}

	// Generate the GCM cipher text.
	nonce := make([]byte, rootKey.NonceSize())
	if _, err := cryptoRand.Read(nonce); err != nil {
		return err
	}
	var key [32]byte
	if _, err := cryptoRand.Read(key[:]); err != nil {
		return err
	}
	config := userConfig
	config.Version = CurrentVersion
	config.Key = key[:]
	if err := validateNormalizeConfig(&config); err != nil {
		return err
	}
	data, err := protobuf.Marshal(&config)
	if err != nil {
		return err
	}
	cipher := rootKey.Seal(nil, nonce, data[:], nil)
	var content []byte
	content = append(content, nonce...)
	content = append(content, cipher...)

	// Create the file and write out cipher text.
	f, err := inner.OpenFile(
		filepath.Join(path, subcipherName),
		os.O_RDWR|os.O_CREATE|os.O_EXCL, os.FileMode(0644))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(content); err != nil {
		return err
	}
	return nil
}

// Fs implements the filesystem of enigma.
type Fs struct {
	inner  afero.Fs
	config *Config
	prefix string
	block  cipher.Block

	// readWrite imples whether the filesystem is read write.
	readWrite bool
	rack      *fileSyncMapRack

	// cache is used for storing recently generated path
	// nonce data. This eliminate the need for calculating
	// the nonce from the root of path.
	cache     *lru.TwoQueueCache
	cacheRoot *cacheValue
}

type option struct {
	cacheSize  int
	readWrite  bool
	writerName string
}

// newOption initializes and sets the default parameter for
// the options.
func newOption() *option {
	return &option{
		cacheSize: 32,
	}
}

// Option specified extra parameters for creating filesystem.
type Option func(*option)

// WithCacheSize sets the cache size of the internal LRU cache.
func WithCacheSize(size int) Option {
	return func(opt *option) {
		opt.cacheSize = size
	}
}

// WithReadWrite implies the file system is read write mode.
//
// The file system fails to initialize when there's another
// process on the same machine or remote file system has
// already claimed it.
//
// The user can find out who is claiming it and restore it to
// normal state if they are sure this is unexpected.
func WithReadWrite(rw bool) Option {
	return func(opt *option) {
		opt.readWrite = rw
	}
}

// WithWriterName sets the instance name of the writer when
// it will be run in writer mode.
//
// Adding this flag will replace the original writer name and
// is more semantic when the process is managed by us.
func WithWriterName(name string) Option {
	return func(opt *option) {
		opt.writerName = name
	}
}

// WithOptions specifies a set of options as a single option.
func WithOptions(options ...Option) Option {
	return func(opt *option) {
		for _, option := range options {
			option(opt)
		}
	}
}

// New the filesystem at specified path.
//
// The specified filesystem must have been initialized by
// the Init function above, and generated with the same
// key as the specified one.
//
// The root key is just used for decrypting the subcipher and
// no longer required after the filesystem is initialized.
func New(
	inner afero.Fs, rootKey cipher.AEAD, path string,
	options ...Option,
) (*Fs, error) {
	nonceSize := rootKey.NonceSize()

	// Apply options and create the objects specified.
	opt := newOption()
	WithOptions(options...)(opt)
	cache, err := lru.New2Q(opt.cacheSize)
	if err != nil {
		return nil, errors.Wrap(err, "create LRU cache")
	}

	// Attempt to read from the specified file and decrypt.
	subcipherPath := filepath.Join(path, subcipherName)
	errReadCipher := func(err error) error {
		return errors.Wrapf(err, "read subcipher %q", subcipherName)
	}
	data, err := afero.ReadFile(inner, subcipherPath)
	if err != nil {
		return nil, errReadCipher(err)
	}
	if len(data) < nonceSize {
		return nil, errReadCipher(errors.New("malformed data"))
	}
	nonce := data[:nonceSize]
	cipher := data[nonceSize:]
	configData, err := rootKey.Open(nil, nonce, cipher, nil)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt config")
	}
	config := &Config{}
	if err := protobuf.Unmarshal(configData, config); err != nil {
		return nil, errors.Wrap(err, "decode config")
	}
	if err := validateNormalizeConfig(config); err != nil {
		return nil, errors.Wrap(err, "validate config")
	}
	key := config.Key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "create subcipher")
	}

	// Collect the result. This is done here in case of possible
	// panics creating dangling files here.
	result := &Fs{
		inner:  inner,
		config: config,
		prefix: path,
		block:  block,
		cache:  cache,
		cacheRoot: &cacheValue{
			nonce:  newNonce(key),
			prefix: "",
		},
		readWrite: opt.readWrite,
	}

	// Attempt to claim control of the file system when it is
	// open in read write mode.
	if opt.readWrite {
		result.rack = newFileSyncMapRack()
		writerPath := filepath.Join(path, writerName)
		f, err := inner.OpenFile(
			writerPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, os.FileMode(0644))
		if err != nil {
			if os.IsExist(err) {
				data, _ := afero.ReadFile(inner, writerPath)
				return nil, errors.Errorf(
					"file system already locked by %q", string(data))
			}
			return nil, errors.Wrap(err, "create lock file")
		}
		lockDone := false
		defer func() {
			_ = f.Close()
			if !lockDone {
				_ = inner.Remove(writerPath)
			}
		}()

		// Attempt to obtain the name of the writer.
		writerName := opt.writerName
		if writerName == "" {
			hostname, err := os.Hostname()
			if err != nil {
				return nil, errors.Wrap(err, "obtain host name")
			}
			pid := os.Getpid()
			writerName = fmt.Sprintf("%s:%d", hostname, pid)
		}

		// Write to the lock file. I feel like this has nothing
		// to do with the underlying file system, so it is okay
		// to store plain text of it.
		if _, err := f.Write([]byte(writerName)); err != nil {
			return nil, errors.Wrap(err, "write lock file")
		}
		lockDone = true
	}

	// It is good to go now since everything is in place.
	return result, nil
}

// Close the file system, removing locks and temporary files.
func (efs *Fs) Close() {
	if efs.readWrite {
		_ = efs.inner.Remove(filepath.Join(efs.prefix, writerName))
	}
}

// cacheValue is the value stored in Fs.cache, which is the
// evaluated content of path's prefix and nonce.
type cacheValue struct {
	nonce  nonceType
	prefix string
}

// evaluateCacheValue attempts to evaluate the cache value
// corresponding to specified path. Result will be cached.
func (efs *Fs) evaluateCacheValue(path string) *cacheValue {
	if val, ok := efs.cache.Get(path); ok {
		return val.(*cacheValue)
	}
	dir, file := filepath.Split(path)
	if file == "" && len(dir) > 0 { // "<path>/"
		dir, file = filepath.Split(dir[:len(dir)-1])
	}
	parentCache := efs.cacheRoot
	if dir != "" {
		parentCache = efs.evaluateCacheValue(dir)
	}
	if file == "" {
		return parentCache
	}
	name := []byte(file)
	nonce := parentCache.nonce.evaluateNonce(name)
	component := parentCache.nonce.encryptName(
		efs.config, efs.block, name)
	result := &cacheValue{
		nonce:  nonce,
		prefix: filepath.Join(parentCache.prefix, component),
	}
	efs.cache.Add(path, result)
	return result
}

// evaluateCleanPath evaluate the ptah relative to the
// inner file system. This comes handy for those don't
// need the cache value.
func (efs *Fs) evaluateCleanPath(cleanPath string) string {
	value := efs.evaluateCacheValue(cleanPath)
	return filepath.Join(efs.prefix, value.prefix)
}

func (efs *Fs) Mkdir(name string, perm os.FileMode) error {
	name = CleanPath(name)
	if !efs.readWrite {
		return pathError("mkdir", name, syscall.EROFS)
	}
	p := efs.evaluateCleanPath(name)
	return cleansePathError(name, efs.inner.Mkdir(p, perm))
}

func (efs *Fs) MkdirAll(name string, perm os.FileMode) error {
	name = CleanPath(name)
	if !efs.readWrite {
		return pathError("mkdir", name, syscall.EROFS)
	}
	p := efs.evaluateCleanPath(name)
	return cleansePathError(name, efs.inner.MkdirAll(p, perm))
}

func (efs *Fs) statCleanPath(name string) (os.FileInfo, error) {
	p := efs.evaluateCleanPath(name)
	info, err := efs.inner.Stat(p)
	if err != nil {
		return nil, cleansePathError(name, err)
	}
	n := filepath.Base(name)
	return &fileInfo{name: n, info: info}, nil
}

func (efs *Fs) Stat(name string) (os.FileInfo, error) {
	return efs.statCleanPath(CleanPath(name))
}

func (*Fs) Name() string {
	return "enigma"
}

func (efs *Fs) Chmod(name string, mode os.FileMode) error {
	name = CleanPath(name)
	if !efs.readWrite {
		return pathError("chmod", name, syscall.EROFS)
	}
	p := efs.evaluateCleanPath(name)
	return cleansePathError(name, efs.inner.Chmod(p, mode))
}

func (efs *Fs) Chown(name string, uid, gid int) error {
	name = CleanPath(name)
	if !efs.readWrite {
		return pathError("chown", name, syscall.EROFS)
	}
	p := efs.evaluateCleanPath(name)
	return cleansePathError(name, efs.inner.Chown(p, uid, gid))
}

func (efs *Fs) Chtimes(name string, atime, mtime time.Time) error {
	name = CleanPath(name)
	if !efs.readWrite {
		return pathError("chtimes", name, syscall.EROFS)
	}
	p := efs.evaluateCleanPath(name)
	return cleansePathError(name, efs.inner.Chtimes(p, atime, mtime))
}

func (efs *Fs) Create(name string) (afero.File, error) {
	return efs.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

func (efs *Fs) Open(name string) (afero.File, error) {
	return efs.OpenFile(name, os.O_RDONLY, 0)
}

func (efs *Fs) removeDir(name string) error {
	dirents, err := afero.ReadDir(efs, name)
	if err != nil {
		return err
	}
	for _, dirent := range dirents {
		path := filepath.Join(name, dirent.Name())
		if dirent.IsDir() {
			if err := efs.removeDir(path); err != nil {
				return err
			}
		}
		if err := efs.Remove(path); err != nil {
			return err
		}
	}
	return nil
}

func (efs *Fs) RemoveAll(name string) error {
	name = CleanPath(name)
	info, err := efs.statCleanPath(name)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err := efs.removeDir(name); err != nil {
			return err
		}
		if name == "" || name == "/" {
			return nil
		}
	}
	return efs.Remove(name)
}

func (efs *Fs) renameFile(
	src, dst string, mode os.FileMode, replace bool,
) error {
	srcFile, err := efs.Open(src)
	if err != nil {
		return err
	}
	defer func() {
		if srcFile != nil {
			_ = srcFile.Close()
		}
	}()
	dstFile, err := efs.OpenFile(
		dst, os.O_RDWR|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		if !os.IsExist(err) || !replace {
			return err
		}
		if err := efs.Remove(dst); err != nil {
			return err
		}
		dstFile, err = efs.OpenFile(
			dst, os.O_RDWR|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
	}
	defer func() { _ = dstFile.Close() }()
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}
	if err := srcFile.Close(); err != nil {
		return err
	}
	srcFile = nil
	return efs.Remove(src)
}

func (efs *Fs) mergeDir(src, dst string) error {
	dentries, err := afero.ReadDir(efs, src)
	if err != nil {
		return err
	}
	for _, dentry := range dentries {
		name := dentry.Name()
		srcPath := filepath.Join(src, name)
		dstPath := filepath.Join(dst, name)
		mode := dentry.Mode()
		if dentry.IsDir() {
			if err := efs.Mkdir(dstPath, mode); err != nil {
				if !os.IsExist(err) {
					return err
				}
			}
			if err := efs.mergeDir(srcPath, dstPath); err != nil {
				return err
			}
			if err := efs.Remove(srcPath); err != nil {
				return err
			}
		} else {
			if err := efs.renameFile(
				srcPath, dstPath, mode, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func underCleanPath(a, b string) (bool, bool) {
	// XXX: since the is clean, adding a slash component can be
	// used to determine the path relationship.
	a = filepath.ToSlash(a) + "/"
	b = filepath.ToSlash(b) + "/"
	return strings.HasPrefix(a, b), strings.HasPrefix(b, a)
}

func (efs *Fs) Merge(src, dst string) error {
	src = CleanPath(src)
	dst = CleanPath(dst)
	srcUnderDst, dstUnderSrc := underCleanPath(src, dst)
	if !srcUnderDst && dstUnderSrc {
		return pathError(src, "rename", syscall.EINVAL)
	}
	srcInfo, err := efs.Stat(src)
	if err != nil {
		return err
	}
	if srcUnderDst && dstUnderSrc {
		return nil
	}
	mode := srcInfo.Mode()
	dstInfo, err := efs.Stat(dst)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if dstInfo != nil && srcInfo.IsDir() != dstInfo.IsDir() {
		return pathError(dst, "rename", syscall.EEXIST)
	}
	if srcInfo.IsDir() {
		if dstInfo == nil {
			err := efs.Mkdir(dst, mode)
			if err != nil && !os.IsExist(err) {
				return err
			}
		}
		if err := efs.mergeDir(src, dst); err != nil {
			return err
		}
		return efs.Remove(src)
	} else {
		return efs.renameFile(src, dst, mode, true)
	}
}

func (efs *Fs) Rename(src, dst string) error {
	src = CleanPath(src)
	dst = CleanPath(dst)
	srcUnderDst, dstUnderSrc := underCleanPath(src, dst)
	if !srcUnderDst && dstUnderSrc {
		return pathError(src, "rename", syscall.EINVAL)
	}
	srcInfo, err := efs.Stat(src)
	if err != nil {
		return err
	}
	if srcUnderDst && dstUnderSrc {
		return nil
	}
	mode := srcInfo.Mode()
	// XXX: the difference here is that the rename will always
	// fail if the destination file already exists. Since not
	// all file system supports such manner. However this is
	// okay since it is mainly used as remote file system.
	_, err = efs.Stat(dst)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		return pathError(dst, "rename", syscall.EEXIST)
	}
	if srcInfo.IsDir() {
		// XXX: please notice the difference here, we must
		// ensure we are the one to create the directory.
		if err := efs.Mkdir(dst, mode); err != nil {
			return err
		}
		if err := efs.mergeDir(src, dst); err != nil {
			return err
		}
		return efs.Remove(src)
	} else {
		return efs.renameFile(src, dst, mode, false)
	}
}
