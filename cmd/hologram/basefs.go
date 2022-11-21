package main

import (
	"github.com/aegistudio/shaft"
	"github.com/spf13/afero"
)

var osfsPath string

func init() {
	rootCmd.PersistentFlags().StringVar(
		&osfsPath, "path", osfsPath,
		"specify local path as base file system")
	options = append(options, shaft.Provide(func() []*baseFsPath {
		var result []*baseFsPath
		if osfsPath != "" {
			result = append(result, &baseFsPath{
				baseFs: afero.NewOsFs(),
				path:   osfsPath,
			})
		}
		return result
	}))
}
