package main

import (
	"os"

	"github.com/aegistudio/go-winfsp"
	"github.com/aegistudio/go-winfsp/gofs"
	"github.com/aegistudio/shaft"
	"github.com/aegistudio/shaft/serpent"
	"github.com/spf13/cobra"

	"github.com/aegistudio/enigma"
)

var (
	winfspMountPoint = "Q:"
	winfspReadOnly   = false
)

type winfspFileSystem struct {
	hfs *enigma.Fs
}

func (fs *winfspFileSystem) OpenFile(
	name string, flags int, perm os.FileMode,
) (gofs.File, error) {
	return fs.hfs.OpenFile(name, flags, perm)
}

func (fs *winfspFileSystem) Mkdir(
	name string, perm os.FileMode,
) error {
	return fs.hfs.Mkdir(name, perm)
}

func (fs *winfspFileSystem) Stat(
	name string,
) (os.FileInfo, error) {
	return fs.hfs.Stat(name)
}

func (fs *winfspFileSystem) Rename(
	source, target string,
) error {
	// TODO: assign better and more semantical names for them.
	return fs.hfs.Merge(source, target)
}

func (fs *winfspFileSystem) Remove(name string) error {
	return fs.hfs.Remove(name)
}

var cmdWinFSP = &cobra.Command{
	Use:   "winfsp",
	Short: "serve enigma file system as WinFSP drive",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if !winfspReadOnly {
			return serpent.AddOption(cmd, withReadWriteOption)
		}
		return nil
	},
	RunE: serpent.Executor(shaft.Module(
		shaft.Invoke(func(
			rootCtx serpent.CommandContext, hfs *enigma.Fs,
		) error {
			fs, err := winfsp.Mount(
				gofs.New(&winfspFileSystem{
					hfs: hfs,
				}), winfspMountPoint,
				winfsp.FileSystemName("Enigma"),
				winfsp.CaseSensitive(true),
			)
			if err != nil {
				return err
			}
			defer fs.Unmount()
			<-rootCtx.Done()
			return nil
		}),
	)).RunE,
}

func init() {
	cmdWinFSP.PersistentFlags().StringVarP(
		&winfspMountPoint, "mount", "m", winfspMountPoint,
		"volume label or network location for mounting")
	cmdWinFSP.PersistentFlags().BoolVar(
		&winfspReadOnly, "read-only", winfspReadOnly,
		"serve the WinFSP drive in read only mode")
	rootCmd.AddCommand(cmdWinFSP)
}
