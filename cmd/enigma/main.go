package main

import (
	"context"
	"crypto/cipher"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"github.com/aegistudio/shaft"
	"github.com/aegistudio/shaft/serpent"
	"github.com/pkg/errors"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/aegistudio/enigma"
)

type baseFsPath struct {
	baseFs afero.Fs
	path   string
}

var options []shaft.Option

var withReadWriteOption = shaft.Supply([]enigma.Option{
	enigma.WithReadWrite(true),
})

var rootCmd = &cobra.Command{
	Use:   "enigma",
	Short: "a simple encrypted file system",
	Long: strings.Trim(`
Enigma command line provides utilities and tools for
setting up the enigma file system as a unix file system
(e.g. FUSE or NFS) or as services (e.g. FTP server), and
managing or diagnosing the file system itself.
`, "\r\n"),
	PreRunE: serpent.Executor(shaft.Module(
		shaft.Provide(func(in []*baseFsPath) (*baseFsPath, error) {
			if len(in) == 0 {
				return nil, errors.New("missing base file")
			}
			if len(in) > 1 {
				return nil, errors.New("ambigious base file system")
			}
			return in[0], nil
		}),
		shaft.Provide(func(in []cipher.AEAD) (cipher.AEAD, error) {
			if len(in) == 0 {
				return nil, errors.New("missing root key")
			}
			if len(in) > 1 {
				return nil, errors.New("ambigious root key")
			}
			return in[0], nil
		}),
		shaft.Stack(func(
			next func(*enigma.Fs) error,
			base *baseFsPath, aead cipher.AEAD, opts []enigma.Option,
		) error {
			fs, err := enigma.New(base.baseFs, aead, base.path, opts...)
			if err != nil {
				return err
			}
			defer fs.Close()
			aead = nil
			runtime.GC()
			return next(fs)
		}),
	)).PreRunE,
}

func main() {
	rootCtx := context.Background()
	rootCtx, cancel := signal.NotifyContext(rootCtx, os.Interrupt)
	defer cancel()
	if err := serpent.ExecuteContext(
		rootCtx, rootCmd, options...); err != nil {
		os.Exit(1)
	}
}
