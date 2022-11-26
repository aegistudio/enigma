//go:build windows
// +build windows

package main

import (
	"github.com/aegistudio/shaft"
	"github.com/aegistudio/shaft/serpent"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/winfsp/cgofuse/fuse"

	"github.com/aegistudio/enigma"
	"github.com/aegistudio/enigma/cgofuse"
)

var (
	winFSPMountPoint = "Q:"
	winFSPReadOnly   = false
)

var cmdWinFSP = &cobra.Command{
	Use:   "winfsp",
	Short: "serve enigma file system via WinFSP",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if !winFSPReadOnly {
			return serpent.AddOption(cmd, withReadWriteOption)
		}
		return nil
	},
	RunE: serpent.Executor(shaft.Module(
		shaft.Invoke(func(
			rootCtx serpent.CommandContext, hfs *enigma.Fs,
			args serpent.CommandArgs,
		) error {
			driver := cgofuse.New(hfs)
			host := fuse.NewFileSystemHost(driver)
			if !host.Mount(winFSPMountPoint, nil) {
				return errors.New("cannot mount WinFSP")
			}
			defer func() { _ = host.Unmount() }()
			<-rootCtx.Done()
			return nil
		}),
	)).RunE,
}

func init() {
	cmdWinFSP.PersistentFlags().StringVar(
		&winFSPMountPoint, "addr", winFSPMountPoint,
		"mount point of the WinFSP file system")
	cmdWinFSP.PersistentFlags().BoolVar(
		&winFSPReadOnly, "read-only", winFSPReadOnly,
		"serve the WinFSP in read only mode")
	rootCmd.AddCommand(cmdWinFSP)
}
