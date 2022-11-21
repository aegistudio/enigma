package main

import (
	"net"
	"net/http"

	"github.com/aegistudio/shaft"
	"github.com/aegistudio/shaft/serpent"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/aegistudio/hologram"
)

var (
	httpListenNetwork = "tcp"
	httpListenAddr    = ":8000"
	httpListenBase    = "/"
)

var cmdHTTP = &cobra.Command{
	Use:   "http",
	Short: "serve hologram file system via HTTP server",
	RunE: serpent.Executor(shaft.Module(
		shaft.Invoke(func(
			rootCtx serpent.CommandContext, hfs *hologram.Fs,
		) error {
			listener, err := net.Listen(
				httpListenNetwork, httpListenAddr)
			if err != nil {
				return err
			}
			defer func() { _ = listener.Close() }()
			group, ctx := errgroup.WithContext(rootCtx)
			defer func() { _ = group.Wait() }()
			httpFs := afero.NewHttpFs(hfs)
			mux := http.NewServeMux()
			mux.Handle(httpListenBase, http.FileServer(httpFs))
			var server http.Server
			server.Handler = mux
			defer func() { _ = server.Close() }()
			group.Go(func() error {
				return server.Serve(listener)
			})
			group.Go(func() error {
				<-ctx.Done()
				_ = server.Close()
				return nil
			})
			return group.Wait()
		}),
	)).RunE,
}

func init() {
	cmdHTTP.PersistentFlags().StringVar(
		&httpListenNetwork, "net", httpListenNetwork,
		"network for the HTTP server to listen")
	cmdHTTP.PersistentFlags().StringVar(
		&httpListenAddr, "addr", httpListenAddr,
		"address for the HTTP server to listen")
	cmdHTTP.PersistentFlags().StringVar(
		&httpListenBase, "uri-path", httpListenBase,
		"path base in URI for the HTTP server to listen")
	rootCmd.AddCommand(cmdHTTP)
}
