package main

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aegistudio/shaft"
	"github.com/aegistudio/shaft/serpent"
	billy "github.com/go-git/go-billy/v5"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	nfs "github.com/willscott/go-nfs"
	nfshelper "github.com/willscott/go-nfs/helpers"
	"golang.org/x/sync/errgroup"

	"github.com/aegistudio/hologram"
)

const (
	nfsReadOnlyCapabilities = billy.ReadCapability |
		billy.SeekCapability | billy.TruncateCapability

	nfsReadWriteCapabilities = nfsReadOnlyCapabilities |
		billy.WriteCapability | billy.ReadAndWriteCapability
)

func unsupportedError(op, path string) error {
	return &os.PathError{Op: op, Path: path, Err: syscall.ENOSYS}
}

type nfsFile struct {
	afero.File
}

func (f nfsFile) unsupportedError(op string) error {
	return unsupportedError(op, f.Name())
}

func (f nfsFile) Lock() error {
	return f.unsupportedError("lock")
}

func (f nfsFile) Unlock() error {
	return f.unsupportedError("unlock")
}

func nfsWrapFileError(f afero.File, err error) (billy.File, error) {
	if err != nil {
		return nil, err
	}
	return &nfsFile{File: f}, nil
}

type nfsFileSystem struct {
	hfs *hologram.Fs
}

func (nfs *nfsFileSystem) Create(filename string) (billy.File, error) {
	return nfsWrapFileError(nfs.hfs.Create(filename))
}

func (nfs *nfsFileSystem) Open(filename string) (billy.File, error) {
	return nfsWrapFileError(nfs.hfs.Open(filename))
}

func (nfs *nfsFileSystem) OpenFile(
	filename string, flag int, perm os.FileMode,
) (billy.File, error) {
	return nfsWrapFileError(nfs.hfs.OpenFile(filename, flag, perm))
}

func (nfs *nfsFileSystem) Stat(filename string) (os.FileInfo, error) {
	return nfs.hfs.Stat(filename)
}

func (nfs *nfsFileSystem) Lstat(filename string) (os.FileInfo, error) {
	// XXX: since there's no symbolic link in the file system
	// currently, it is just equivalent to using Stat here.
	return nfs.hfs.Stat(filename)
}

func (nfs *nfsFileSystem) Rename(oldpath, newpath string) error {
	return nfs.hfs.Rename(oldpath, newpath)
}

func (nfs *nfsFileSystem) Remove(filename string) error {
	return nfs.hfs.Remove(filename)
}

func (nfs *nfsFileSystem) Join(elem ...string) string {
	return filepath.Join(elem...)
}

func (nfs *nfsFileSystem) TempFile(dir, prefix string) (billy.File, error) {
	return nfsWrapFileError(afero.TempFile(nfs.hfs, dir, prefix))
}

func (nfs *nfsFileSystem) ReadDir(path string) ([]os.FileInfo, error) {
	return afero.ReadDir(nfs.hfs, path)
}

func (nfs *nfsFileSystem) MkdirAll(filename string, perm os.FileMode) error {
	return nfs.hfs.MkdirAll(filename, perm)
}

func (nfs *nfsFileSystem) Chmod(name string, mode os.FileMode) error {
	return nfs.hfs.Chmod(name, mode)
}

func (nfs *nfsFileSystem) Lchown(name string, uid, gid int) error {
	// XXX: since there's no symbolic link in the file system
	// currently, it is just equivalent to using Chown here.
	return nfs.hfs.Chown(name, uid, gid)
}

func (nfs *nfsFileSystem) Chown(name string, uid, gid int) error {
	return nfs.hfs.Chown(name, uid, gid)
}

func (nfs *nfsFileSystem) Chtimes(name string, atime, mtime time.Time) error {
	return nfs.hfs.Chtimes(name, atime, mtime)
}

func (nfs *nfsFileSystem) Symlink(target, link string) error {
	return unsupportedError(link, "symlink")
}

func (nfs *nfsFileSystem) Readlink(link string) (string, error) {
	return "", unsupportedError(link, "readlink")
}

func (nfs *nfsFileSystem) Chroot(path string) (billy.Filesystem, error) {
	return nil, unsupportedError(path, "chroot")
}

func (nfs *nfsFileSystem) Root() string {
	return "/"
}

var (
	nfsListenNetwork = "tcp"
	nfsListenAddr    = ":2049"
	nfsReadOnly      = false
)

var cmdNFSv3 = &cobra.Command{
	Use:   "nfsv3",
	Short: "serve hologram file system via NFSv3 server",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if !ftpReadOnly {
			return serpent.AddOption(cmd, withReadWriteOption)
		}
		return nil
	},
	RunE: serpent.Executor(shaft.Module(
		shaft.Invoke(func(
			rootCtx serpent.CommandContext, hfs *hologram.Fs,
		) error {
			listener, err := net.Listen(
				nfsListenNetwork, nfsListenAddr)
			if err != nil {
				return err
			}
			defer func() { _ = listener.Close() }()
			group, ctx := errgroup.WithContext(rootCtx)
			defer func() { _ = group.Wait() }()
			fs := &nfsFileSystem{hfs: hfs}
			handler := nfshelper.NewNullAuthHandler(fs)
			cacheHelper := nfshelper.NewCachingHandler(handler, 1024)
			server := nfs.Server{
				Context: ctx,
				Handler: cacheHelper,
			}
			group.Go(func() error {
				return server.Serve(listener)
			})
			group.Go(func() error {
				<-ctx.Done()
				_ = listener.Close()
				return nil
			})
			return group.Wait()
		}),
	)).RunE,
}

func init() {
	cmdNFSv3.PersistentFlags().StringVar(
		&nfsListenNetwork, "net", nfsListenNetwork,
		"network for the NFSv3 server to listen")
	cmdNFSv3.PersistentFlags().StringVar(
		&nfsListenAddr, "addr", nfsListenAddr,
		"address for the NFSv3 server to listen")
	cmdNFSv3.PersistentFlags().BoolVar(
		&nfsReadOnly, "read-only", nfsReadOnly,
		"serve the NFSv3 server in read only mode")
	rootCmd.AddCommand(cmdNFSv3)
}
