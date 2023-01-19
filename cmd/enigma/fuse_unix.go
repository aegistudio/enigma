//go:build !windows
// +build !windows

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/aegistudio/shaft"
	"github.com/aegistudio/shaft/serpent"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/pkg/errors"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/aegistudio/enigma"
)

var (
	fuseDirectMount = false
	fuseReadOnly    = false
	fuseOptions     []string
)

type fuseFileNode struct {
	fs.Inode
	hfs  *enigma.Fs
	path string
}

func fuseConvertFileMode(mode os.FileMode) uint32 {
	var result uint32
	switch mode.Type() {
	case 0: // ModeRegular
		result |= syscall.S_IFREG
	case os.ModeDir:
		result |= syscall.S_IFDIR
	case os.ModeDevice:
		result |= syscall.S_IFBLK
	case os.ModeDevice | os.ModeCharDevice:
		result |= syscall.S_IFCHR
	case os.ModeSymlink:
		result |= syscall.S_IFLNK
	case os.ModeNamedPipe:
		result |= syscall.S_IFIFO
	case os.ModeSocket:
		result |= syscall.S_IFSOCK
	default:
		result |= syscall.S_IFMT
	}
	if mode&os.FileMode(0400) != 0 {
		result |= syscall.S_IRUSR
	}
	if mode&os.FileMode(0200) != 0 {
		result |= syscall.S_IWUSR
	}
	if mode&os.FileMode(0100) != 0 {
		result |= syscall.S_IXUSR
	}
	if mode&os.FileMode(0040) != 0 {
		result |= syscall.S_IRGRP
	}
	if mode&os.FileMode(0020) != 0 {
		result |= syscall.S_IWGRP
	}
	if mode&os.FileMode(0010) != 0 {
		result |= syscall.S_IXGRP
	}
	if mode&os.FileMode(0004) != 0 {
		result |= syscall.S_IROTH
	}
	if mode&os.FileMode(0002) != 0 {
		result |= syscall.S_IWOTH
	}
	if mode&os.FileMode(0001) != 0 {
		result |= syscall.S_IXOTH
	}
	if mode&os.ModeSetuid != 0 {
		result |= syscall.S_ISUID
	}
	if mode&os.ModeSetgid != 0 {
		result |= syscall.S_ISGID
	}
	if mode&os.ModeSticky != 0 {
		result |= syscall.S_ISVTX
	}
	return result
}

func fuseFillStat(fileInfo os.FileInfo) fuse.Attr {
	var result fuse.Attr
	result.Mode = fuseConvertFileMode(fileInfo.Mode())
	result.Ino = 0
	result.Rdev = 0
	result.Size = uint64(fileInfo.Size())
	modTime := fileInfo.ModTime()
	if result.Atime == 0 && result.Atimensec == 0 {
		result.Atime = uint64(modTime.Unix())
		result.Atimensec = uint32(modTime.Nanosecond())
	}
	if result.Mtime == 0 && result.Mtimensec == 0 {
		result.Mtime = uint64(modTime.Unix())
		result.Mtimensec = uint32(modTime.Nanosecond())
	}
	if result.Ctime == 0 && result.Ctimensec == 0 {
		result.Ctime = uint64(modTime.Unix())
		result.Ctimensec = uint32(modTime.Nanosecond())
	}
	if sys := fileInfo.Sys(); sys != nil {
		switch s := sys.(type) {
		case *syscall.Stat_t:
			// We don't wish to pass all attributes to the
			// caller, since it is not a real passthrough.
			fuseFillWithStat(&result, s)
		}
	}
	return result
}

func (n *fuseFileNode) Lookup(
	ctx context.Context, name string, out *fuse.EntryOut,
) (*fs.Inode, syscall.Errno) {
	path := filepath.Join(n.path, name)
	fileInfo, err := n.hfs.Stat(path)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	out.Attr = fuseFillStat(fileInfo)
	return n.NewInode(ctx, &fuseFileNode{
		hfs:  n.hfs,
		path: path,
	}, fs.StableAttr{
		Mode: out.Attr.Mode,
		Gen:  1,
	}), 0
}

var _ fs.NodeLookuper = (*fuseFileNode)(nil)

func (n *fuseFileNode) Readdir(
	ctx context.Context,
) (fs.DirStream, syscall.Errno) {
	// XXX: since the entrypted filename's order is very likely
	// to be different from the plaintext filename, the underlying
	// directory file will always read all directory entries,
	// opening a file and encapsulate it as something like
	// fuseDirStream has nearly no optimization.
	dirents, err := afero.ReadDir(n.hfs, n.path)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	var result []fuse.DirEntry
	for _, dirent := range dirents {
		result = append(result, fuse.DirEntry{
			Mode: fuseConvertFileMode(dirent.Mode()),
			Name: dirent.Name(),
		})
	}
	return fs.NewListDirStream(result), 0
}

var _ fs.NodeReaddirer = (*fuseFileNode)(nil)

type fuseFileHandle struct {
	file   afero.File
	append bool
}

func (fh *fuseFileHandle) Release(
	ctx context.Context,
) syscall.Errno {
	return fs.ToErrno(fh.file.Close())
}

var _ fs.FileReleaser = (*fuseFileHandle)(nil)

func (fh *fuseFileHandle) Read(
	ctx context.Context, dest []byte, off int64,
) (fuse.ReadResult, syscall.Errno) {
	n, err := fh.file.ReadAt(dest, off)
	result := fuse.ReadResultData(dest[:n])
	if errors.Is(err, io.EOF) {
		err = nil
	}
	if err != nil {
		return result, fs.ToErrno(err)
	}
	return result, 0
}

var _ fs.FileReader = (*fuseFileHandle)(nil)

func (fh *fuseFileHandle) Write(
	ctx context.Context, data []byte, off int64,
) (uint32, syscall.Errno) {
	var write func([]byte, int64) (int, error) = fh.file.WriteAt
	if fh.append {
		write = func(data []byte, _ int64) (int, error) {
			return fh.file.Write(data)
		}
	}
	n, err := write(data, off)
	if err != nil {
		return uint32(n), fs.ToErrno(err)
	}
	return uint32(n), 0
}

var _ fs.FileWriter = (*fuseFileHandle)(nil)

func (fh *fuseFileHandle) Lseek(
	ctx context.Context, off uint64, whence uint32,
) (uint64, syscall.Errno) {
	ret, err := fh.file.Seek(int64(off), int(whence))
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	return uint64(ret), 0
}

var _ fs.FileLseeker = (*fuseFileHandle)(nil)

// fuseValidFlags contains the flags that are valid from our
// perspective, which might be either interpreted or simply
// igored (as it is handled by kernel).
//
// XXX: I don't know what the flags in 0x8020 mean, but it
// seems to be working well just ignoring the flag.
const fuseValidFlags = syscall.O_ACCMODE | syscall.O_CREAT |
	syscall.O_EXCL | syscall.O_APPEND | syscall.O_TRUNC |
	syscall.O_SYNC | O_DIRECT | syscall.O_DIRECTORY |
	syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_ASYNC |
	syscall.O_NONBLOCK | syscall.O_NDELAY | 0x8020

func fuseConvertUnixOpenFlags(flags uint32) (int, error) {
	if flags&^fuseValidFlags != 0 {
		return 0, syscall.ENOSYS
	}
	var result int
	switch flags & syscall.O_ACCMODE {
	case syscall.O_RDONLY:
		result |= os.O_RDONLY
	case syscall.O_WRONLY:
		result |= os.O_WRONLY
	case syscall.O_RDWR:
		result |= os.O_RDWR
	default:
		return 0, syscall.EINVAL
	}
	if flags&syscall.O_DIRECTORY != 0 {
		if flags&syscall.O_ACCMODE != 0 {
			return 0, syscall.EINVAL
		}
	}
	if flags&syscall.O_APPEND != 0 {
		result |= os.O_APPEND
	}
	if flags&syscall.O_CREAT != 0 {
		result |= os.O_CREATE
	}
	if flags&syscall.O_EXCL != 0 {
		result |= os.O_EXCL
	}
	if flags&(syscall.O_SYNC|O_DIRECT) != 0 {
		result |= os.O_SYNC
	}
	if flags&syscall.O_TRUNC != 0 {
		result |= os.O_TRUNC
	}
	return result, nil
}

func (n *fuseFileNode) openFile(
	ctx context.Context, flags uint32, mode os.FileMode,
) (afero.File, os.FileInfo, error) {
	openFlags, err := fuseConvertUnixOpenFlags(flags)
	if err != nil {
		return nil, nil, err
	}
	f, err := n.hfs.OpenFile(n.path, openFlags, mode)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()
	stat, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if flags&syscall.O_DIRECTORY != 0 {
		if !stat.IsDir() {
			return nil, nil, syscall.ENOTDIR
		}
	}
	result := f
	f = nil
	return result, stat, nil
}

func (n *fuseFileNode) Open(
	ctx context.Context, flags uint32,
) (fs.FileHandle, uint32, syscall.Errno) {
	f, _, err := n.openFile(ctx, flags, os.FileMode(0))
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}
	return &fuseFileHandle{
		file:   f,
		append: flags&syscall.O_APPEND != 0,
	}, fuse.FOPEN_DIRECT_IO, 0
}

var _ fs.NodeOpener = (*fuseFileNode)(nil)

const fuseValidMode = syscall.S_IFMT |
	syscall.S_ISUID | syscall.S_ISGID | syscall.S_ISVTX |
	syscall.S_IRWXU | syscall.S_IRWXG | syscall.S_IRWXO

func fuseConvertUnixFileMode(mode uint32) (os.FileMode, error) {
	if mode&^fuseValidMode != 0 {
		return 0, syscall.ENOSYS
	}
	var result os.FileMode
	switch mode & syscall.S_IFMT {
	case 0, syscall.S_IFREG:
	case syscall.S_IFDIR:
		result |= os.ModeDir
	case syscall.S_IFBLK:
		result |= os.ModeDevice
	case syscall.S_IFCHR:
		result |= os.ModeCharDevice | os.ModeDevice
	case syscall.S_IFIFO:
		result |= os.ModeNamedPipe
	case syscall.S_IFLNK:
		result |= os.ModeSymlink
	case syscall.S_IFSOCK:
		result |= os.ModeSocket
	default:
		return 0, syscall.EINVAL
	}
	if mode&syscall.S_IRUSR != 0 {
		result |= os.FileMode(0400)
	}
	if mode&syscall.S_IWUSR != 0 {
		result |= os.FileMode(0200)
	}
	if mode&syscall.S_IXUSR != 0 {
		result |= os.FileMode(0100)
	}
	if mode&syscall.S_IRGRP != 0 {
		result |= os.FileMode(0040)
	}
	if mode&syscall.S_IWGRP != 0 {
		result |= os.FileMode(0020)
	}
	if mode&syscall.S_IXGRP != 0 {
		result |= os.FileMode(0010)
	}
	if mode&syscall.S_IROTH != 0 {
		result |= os.FileMode(0004)
	}
	if mode&syscall.S_IWOTH != 0 {
		result |= os.FileMode(0002)
	}
	if mode&syscall.S_IXOTH != 0 {
		result |= os.FileMode(0001)
	}
	if mode&syscall.S_ISUID != 0 {
		result |= os.ModeSetuid
	}
	if mode&syscall.S_ISGID != 0 {
		result |= os.ModeSetuid
	}
	if mode&syscall.S_ISVTX != 0 {
		result |= os.ModeSticky
	}
	return result, nil
}

func (n *fuseFileNode) Create(
	ctx context.Context, name string,
	flags, mode uint32, out *fuse.EntryOut,
) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	openMode, err := fuseConvertUnixFileMode(mode)
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
	}
	if !openMode.IsRegular() {
		return nil, nil, 0, syscall.EINVAL
	}
	path := filepath.Join(n.path, name)
	inner := &fuseFileNode{
		hfs:  n.hfs,
		path: path,
	}
	f, fileInfo, err := inner.openFile(
		ctx, flags|syscall.O_CREAT, openMode)
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()
	result := &fuseFileHandle{
		file:   f,
		append: flags&syscall.O_APPEND != 0,
	}
	out.Attr = fuseFillStat(fileInfo)
	inode := n.NewInode(ctx, inner, fs.StableAttr{
		Mode: out.Attr.Mode,
		Gen:  1,
	})
	f = nil
	return inode, result, fuse.FOPEN_DIRECT_IO, 0
}

var _ fs.NodeCreater = (*fuseFileNode)(nil)

func (n *fuseFileNode) getattr(
	ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut,
) error {
	var fileInfo os.FileInfo
	var err error
	if fh != nil {
		if h, ok := fh.(*fuseFileHandle); ok {
			fileInfo, err = h.file.Stat()
			if err != nil {
				return err
			}
		}
	}
	if fileInfo == nil {
		fileInfo, err = n.hfs.Stat(n.path)
		if err != nil {
			return err
		}
	}
	out.Attr = fuseFillStat(fileInfo)
	return nil
}

func (n *fuseFileNode) Getattr(
	ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut,
) syscall.Errno {
	if err := n.getattr(ctx, fh, out); err != nil {
		return fs.ToErrno(err)
	}
	return 0
}

var _ fs.NodeGetattrer = (*fuseFileNode)(nil)

func (n *fuseFileNode) Setattr(
	ctx context.Context, fh fs.FileHandle,
	in *fuse.SetAttrIn, out *fuse.AttrOut,
) syscall.Errno {
	if err := n.getattr(ctx, fh, out); err != nil {
		return fs.ToErrno(err)
	}
	if in.Valid&fuse.FATTR_MODE != 0 {
		openMode, err := fuseConvertUnixFileMode(in.Mode)
		if err != nil {
			return fs.ToErrno(err)
		}
		if err := n.hfs.Chmod(n.path, openMode); err != nil {
			return fs.ToErrno(err)
		}
	}
	if in.Valid&(fuse.FATTR_UID|fuse.FATTR_GID) != 0 {
		// TODO: we will need extra setup to ensure that the process
		// will be able to manipulate the file even after the file's
		// owner has been changed.
		/*
			uid := out.Attr.Uid
			gid := out.Attr.Gid
			if v, ok := in.GetUID(); ok {
				uid = v
			}
			if v, ok := in.GetGID(); ok {
				gid = v
			}
			if err := n.hfs.Chown(n.path, int(uid), int(gid)); err != nil {
				return fs.ToErrno(err)
			}
		*/
		return syscall.ENOSYS
	}
	if in.Valid&fuse.FATTR_SIZE != 0 {
		var file afero.File
		if fh != nil {
			if h, ok := fh.(*fuseFileHandle); ok {
				file = h.file
			}
		}
		if file == nil {
			tempFile, err := n.hfs.OpenFile(
				n.path, os.O_WRONLY, os.FileMode(0))
			if err != nil {
				return fs.ToErrno(err)
			}
			defer func() { _ = tempFile.Close() }()
			file = tempFile
		}
		if err := file.Truncate(int64(in.Size)); err != nil {
			return fs.ToErrno(err)
		}
	}
	if in.Valid&(fuse.FATTR_ATIME|fuse.FATTR_MTIME|
		fuse.FATTR_ATIME_NOW|fuse.FATTR_MTIME_NOW) != 0 {
		atime := out.Attr.AccessTime()
		mtime := out.Attr.ModTime()
		if t, ok := in.GetATime(); ok {
			atime = t
		}
		if t, ok := in.GetMTime(); ok {
			mtime = t
		}
		if err := n.hfs.Chtimes(n.path, atime, mtime); err != nil {
			return fs.ToErrno(err)
		}
	}
	if err := n.getattr(ctx, fh, out); err != nil {
		return fs.ToErrno(err)
	}
	return 0
}

var _ fs.NodeSetattrer = (*fuseFileNode)(nil)

func (n *fuseFileNode) Mkdir(
	ctx context.Context, name string,
	mode uint32, out *fuse.EntryOut,
) (*fs.Inode, syscall.Errno) {
	openMode, err := fuseConvertUnixFileMode(mode)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	path := filepath.Join(n.path, name)
	if err := n.hfs.Mkdir(path, openMode); err != nil {
		return nil, fs.ToErrno(err)
	}
	return n.Lookup(ctx, name, out)
}

var _ fs.NodeMkdirer = (*fuseFileNode)(nil)

func (n *fuseFileNode) Rmdir(
	ctx context.Context, name string,
) syscall.Errno {
	path := filepath.Join(n.path, name)
	if err := n.hfs.Remove(path); err != nil {
		return fs.ToErrno(err)
	}
	return 0
}

var _ fs.NodeRmdirer = (*fuseFileNode)(nil)

func (n *fuseFileNode) Unlink(
	ctx context.Context, name string,
) syscall.Errno {
	path := filepath.Join(n.path, name)
	if err := n.hfs.Remove(path); err != nil {
		return fs.ToErrno(err)
	}
	return 0
}

var _ fs.NodeUnlinker = (*fuseFileNode)(nil)

func (n *fuseFileNode) Rename(
	ctx context.Context, name string,
	newParent fs.InodeEmbedder, newName string, flags uint32,
) syscall.Errno {
	if flags&^RENAME_NOREPLACE != 0 {
		return syscall.ENOSYS
	}
	var rename func(src, dst string) error = n.hfs.Merge
	if flags&RENAME_NOREPLACE != 0 {
		rename = n.hfs.Rename
	}
	newParentNode, ok := newParent.(*fuseFileNode)
	if !ok {
		return syscall.EINVAL
	}
	if err := rename(
		filepath.Join(n.path, name),
		filepath.Join(newParentNode.path, newName),
	); err != nil {
		return fs.ToErrno(err)
	}
	return 0
}

var _ fs.NodeRenamer = (*fuseFileNode)(nil)

var cmdFuse = &cobra.Command{
	Use:   "fuse",
	Args:  cobra.ExactArgs(1),
	Short: "serve enigma file system via FUSE",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if !fuseReadOnly {
			return serpent.AddOption(cmd, withReadWriteOption)
		}
		return nil
	},
	RunE: serpent.Executor(shaft.Module(
		shaft.Invoke(func(
			rootCtx serpent.CommandContext, hfs *enigma.Fs,
			args serpent.CommandArgs,
		) error {
			var options fs.Options
			options.FsName = "enigma"
			options.Name = "enigma"
			options.DirectMount = fuseDirectMount
			options.Options = fuseOptions
			options.DisableXAttrs = true
			server, err := fs.Mount(
				args[0],
				&fuseFileNode{
					hfs:  hfs,
					path: "",
				},
				&options,
			)
			if err != nil {
				return err
			}
			group, ctx := errgroup.WithContext(rootCtx)
			group.Go(func() error {
				if err := server.WaitMount(); err != nil {
					return err
				}
				<-ctx.Done()
				return server.Unmount()
			})
			group.Go(func() error {
				if err := server.WaitMount(); err != nil {
					return err
				}
				server.Wait()
				return nil
			})
			return group.Wait()
		}),
	)).RunE,
}

func init() {
	cmdFuse.PersistentFlags().BoolVar(
		&fuseDirectMount, "direct-mount", fuseDirectMount,
		"use mount system call instead of fusermount")
	cmdFuse.PersistentFlags().BoolVar(
		&fuseReadOnly, "read-only", fuseReadOnly,
		"serve the FUSE file system in read only mode")
	cmdFuse.PersistentFlags().StringArrayVarP(
		&fuseOptions, "option", "o", fuseOptions,
		"specify mount option while mounting")
	rootCmd.AddCommand(cmdFuse)
}
