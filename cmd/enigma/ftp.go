package main

import (
	"crypto/tls"

	"github.com/aegistudio/shaft"
	"github.com/aegistudio/shaft/serpent"
	ftp "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/aegistudio/enigma"
)

var (
	ftpSettings = &ftp.Settings{
		ListenAddr:              ":2121",
		ActiveTransferPortNon20: true,
		Banner:                  "enigma",
	}
	ftpReadOnly = false
)

type ftpMainDriver struct {
	hfs *enigma.Fs
}

func (ftpMainDriver) GetSettings() (*ftp.Settings, error) {
	return ftpSettings, nil
}

func (ftpMainDriver) ClientConnected(ftp.ClientContext) (string, error) {
	return "", nil
}

func (ftpMainDriver) ClientDisconnected(_ ftp.ClientContext) {
}

func (ftpMainDriver) GetTLSConfig() (*tls.Config, error) {
	return nil, nil
}

func (d ftpMainDriver) AuthUser(
	cc ftp.ClientContext, user, pass string,
) (ftp.ClientDriver, error) {
	return d.hfs, nil
}

var cmdFTP = &cobra.Command{
	Use:   "ftp",
	Short: "serve enigma file system via FTP server",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if !ftpReadOnly {
			return serpent.AddOption(cmd, withReadWriteOption)
		}
		return nil
	},
	RunE: serpent.Executor(shaft.Module(
		shaft.Invoke(func(
			rootCtx serpent.CommandContext, hfs *enigma.Fs,
		) error {
			group, ctx := errgroup.WithContext(rootCtx)
			defer func() { _ = group.Wait() }()
			driver := &ftpMainDriver{hfs: hfs}
			server := ftp.NewFtpServer(driver)
			group.Go(func() error {
				return server.ListenAndServe()
			})
			group.Go(func() error {
				<-ctx.Done()
				_ = server.Stop()
				return nil
			})
			return group.Wait()
		}),
	)).RunE,
}

func init() {
	cmdFTP.PersistentFlags().StringVar(
		&ftpSettings.ListenAddr, "addr", ftpSettings.ListenAddr,
		"address for the FTP server to listen")
	cmdFTP.PersistentFlags().StringVar(
		&ftpSettings.Banner, "motd", ftpSettings.Banner,
		"motd for the FTP server to display")
	cmdFTP.PersistentFlags().BoolVar(
		&ftpReadOnly, "read-only", ftpReadOnly,
		"serve the FTP server in read only mode")
	rootCmd.AddCommand(cmdFTP)
}
