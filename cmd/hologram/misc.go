package main

import (
	"crypto/cipher"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aegistudio/shaft"
	"github.com/aegistudio/shaft/serpent"
	"github.com/pkg/errors"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/aegistudio/hologram"
)

var cmdInit = &cobra.Command{
	Use:   "init",
	Short: "initialize hologram file system at path",
	RunE: serpent.Executor(shaft.Invoke(func(
		base *baseFsPath, rootKey cipher.AEAD,
	) error {
		return hologram.Init(base.baseFs, rootKey, base.path)
	})).RunE,
}

func init() {
	rootCmd.AddCommand(cmdInit)
}

var (
	mkdirParents bool
	mkdirPerm    = os.FileMode(0755)
)

var cmdMkdir = &cobra.Command{
	Use:   "mkdir",
	Short: "create directory inside the file system",
	Args:  cobra.MinimumNArgs(1),
	RunE: serpent.Executor(shaft.Module(
		withReadWriteOption,
		shaft.Invoke(func(
			hfs *hologram.Fs, args serpent.CommandArgs,
		) error {
			mkdir := hfs.Mkdir
			if mkdirParents {
				mkdir = hfs.MkdirAll
			}
			for _, dir := range args {
				if err := mkdir(dir, mkdirPerm); err != nil {
					return err
				}
			}
			return nil
		}),
	)).RunE,
}

func init() {
	cmdMkdir.PersistentFlags().BoolVarP(
		&mkdirParents, "parents", "p", mkdirParents,
		"make parent directories as needed")
	rootCmd.AddCommand(cmdMkdir)
}

var (
	teeAppendMode bool
	teePerm       = os.FileMode(0644)
)

var cmdTee = &cobra.Command{
	Use:   "tee",
	Short: "tee command for hologram file system",
	RunE: serpent.Executor(shaft.Module(
		withReadWriteOption,
		shaft.Invoke(func(
			hfs *hologram.Fs, args serpent.CommandArgs,
		) error {
			var writers []io.Writer
			extraMode := os.O_TRUNC
			if teeAppendMode {
				extraMode = os.O_APPEND
			}
			for _, name := range args {
				f, err := hfs.OpenFile(name,
					os.O_RDWR|os.O_CREATE|extraMode, teePerm)
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				writers = append(writers, f)
			}
			writers = append(writers, os.Stdout)
			writer := io.MultiWriter(writers...)
			_, err := io.Copy(writer, os.Stdin)
			return err
		}),
	)).RunE,
}

func init() {
	cmdTee.PersistentFlags().BoolVarP(
		&teeAppendMode, "append", "a", teeAppendMode,
		"append to the given files insted of overwriting")
	rootCmd.AddCommand(cmdTee)
}

var cmdCat = &cobra.Command{
	Use:   "cat",
	Short: "cat command for hologram file system",
	RunE: serpent.Executor(shaft.Module(
		shaft.Invoke(func(
			hfs *hologram.Fs, args serpent.CommandArgs,
		) error {
			for _, name := range args {
				f, err := hfs.Open(name)
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				if _, err := io.Copy(os.Stdout, f); err != nil {
					return err
				}
			}
			return nil
		}),
	)).RunE,
}

func init() {
	rootCmd.AddCommand(cmdCat)
}

var (
	rmRecursive bool
)

var cmdRm = &cobra.Command{
	Use:   "rm",
	Short: "rm command for hologram file system",
	RunE: serpent.Executor(shaft.Module(
		withReadWriteOption,
		shaft.Invoke(func(
			hfs *hologram.Fs, args serpent.CommandArgs,
		) error {
			remove := hfs.Remove
			if rmRecursive {
				remove = hfs.RemoveAll
			}
			for _, name := range args {
				if err := remove(name); err != nil {
					return err
				}
			}
			return nil
		}),
	)).RunE,
}

func init() {
	cmdRm.PersistentFlags().BoolVarP(
		&rmRecursive, "recursive", "r", rmRecursive,
		"remove directories and their contents recursively")
	rootCmd.AddCommand(cmdRm)
}

var (
	mvMerge bool
)

var cmdMv = &cobra.Command{
	Use:   "mv",
	Short: "mv command for hologram file system",
	Args:  cobra.ExactArgs(2),
	RunE: serpent.Executor(shaft.Module(
		withReadWriteOption,
		shaft.Invoke(func(
			hfs *hologram.Fs, args serpent.CommandArgs,
		) error {
			move := hfs.Rename
			if mvMerge {
				move = hfs.Merge
			}
			return move(args[0], args[1])
		}),
	)).RunE,
}

func init() {
	cmdMv.PersistentFlags().BoolVarP(
		&mvMerge, "merge", "m", mvMerge,
		"merge the source dir to the destination dir")
	rootCmd.AddCommand(cmdMv)
}

var (
	lsLongList bool

	lsLineStart  = []byte("\xff")
	lsLineColumn = []byte("\xff\v\xff")
	lsLineEnd    = []byte("\xff\n")
)

func listName(infos []os.FileInfo) error {
	for _, info := range infos {
		fmt.Println(info.Name())
	}
	return nil
}

func listFull(infos []os.FileInfo) error {
	tabWriter := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	defer func() { _ = tabWriter.Flush() }()
	var lines [][]string
	now := time.Now()
	for _, info := range infos {
		var line []string
		line = append(line, info.Mode().String())
		line = append(line, fmt.Sprintf("%d", info.Size()))
		modTime := info.ModTime()
		timeFormat := "Jan _2 15:04"
		if modTime.Year() != now.Year() {
			timeFormat = "Jan _2 2006"
		}
		line = append(line, modTime.Format(timeFormat))
		line = append(line, info.Name())
		lines = append(lines, line)
	}
	for _, line := range lines {
		if _, err := tabWriter.Write(lsLineStart); err != nil {
			return err
		}
		for _, col := range line {
			if _, err := tabWriter.Write([]byte(col)); err != nil {
				return err
			}
			if _, err := tabWriter.Write(lsLineColumn); err != nil {
				return err
			}
		}
		if _, err := tabWriter.Write(lsLineEnd); err != nil {
			return err
		}
	}
	return nil
}

var cmdLs = &cobra.Command{
	Use:   "ls",
	Short: "ls command for hologram file system",
	RunE: serpent.Executor(shaft.Module(
		shaft.Invoke(func(
			hfs *hologram.Fs, args serpent.CommandArgs,
		) error {
			if len(args) == 0 {
				args = serpent.CommandArgs([]string{"/"})
			}
			var files []os.FileInfo
			var dirs []string
			for _, arg := range args {
				info, err := hfs.Stat(arg)
				if err != nil {
					return err
				}
				if info.IsDir() {
					dirs = append(dirs, arg)
				} else {
					files = append(files, info)
				}
			}
			list := listName
			if lsLongList {
				list = listFull
			}
			if len(files) != 0 {
				if err := list(files); err != nil {
					return err
				}
			}
			if len(files) == 0 && len(dirs) == 1 {
				infos, err := afero.ReadDir(hfs, dirs[0])
				if err != nil {
					return err
				}
				return list(infos)
			}
			firstLine := len(files) == 0
			for _, dir := range dirs {
				if firstLine {
					firstLine = false
				} else {
					fmt.Println("")
				}
				infos, err := afero.ReadDir(hfs, dir)
				if err != nil {
					return err
				}
				fmt.Printf("%s:\n", dir)
				if err := list(infos); err != nil {
					return err
				}
			}
			return nil
		}),
	)).RunE,
}

func init() {
	cmdLs.PersistentFlags().BoolVarP(
		&lsLongList, "long-list", "l", lsLongList,
		"use a long listing format")
	rootCmd.AddCommand(cmdLs)
}

var (
	findNamePattern string
	findType        string
)

var cmdFind = &cobra.Command{
	Use:   "find",
	Short: "find command for hologram file system",
	Args:  cobra.ExactArgs(1),
	RunE: serpent.Executor(shaft.Module(
		shaft.Invoke(func(
			hfs *hologram.Fs, args serpent.CommandArgs,
		) error {
			if findNamePattern != "" {
				if _, err := filepath.Match(
					findNamePattern, "/"); err != nil {
					return err
				}
			}
			if findType != "" {
				if remain := strings.Trim(
					findType, "fd"); remain != "" {
					return errors.Errorf("unknown type %q", remain)
				}
			}
			return afero.Walk(hfs, args[0], func(
				path string, info os.FileInfo, err error,
			) error {
				if err != nil {
					return err
				}
				if findNamePattern != "" {
					if ok, _ := filepath.Match(
						findNamePattern, info.Name()); !ok {
						return nil
					}
				}
				if findType != "" {
					fileType := "f"
					if info.IsDir() {
						fileType = "d"
					}
					if !strings.Contains(findType, fileType) {
						return nil
					}
				}
				fmt.Println(path)
				return nil
			})
		}),
	)).RunE,
}

func init() {
	cmdFind.PersistentFlags().StringVar(
		&findNamePattern, "name", findNamePattern,
		"specify glob pattern for file name")
	cmdFind.PersistentFlags().StringVar(
		&findType, "type", findType,
		"specify acceptable file types")
	rootCmd.AddCommand(cmdFind)
}
