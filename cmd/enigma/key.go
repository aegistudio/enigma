package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"io/ioutil"

	"github.com/aegistudio/shaft"
)

var aes256File string

func init() {
	rootCmd.PersistentFlags().StringVar(
		&aes256File, "aes256", aes256File,
		"read content as AES key from a file")
	options = append(options, shaft.Provide(
		func() ([]cipher.AEAD, error) {
			if aes256File != "" {
				data, err := ioutil.ReadFile(aes256File)
				if err != nil {
					return nil, err
				}
				block, err := aes.NewCipher(data)
				if err != nil {
					return nil, err
				}
				aead, err := cipher.NewGCM(block)
				if err != nil {
					return nil, err
				}
				return []cipher.AEAD{aead}, nil
			}
			return nil, nil
		}))
}

var aes256Sha256File string

func init() {
	rootCmd.PersistentFlags().StringVar(
		&aes256Sha256File, "aes256-sha256", aes256Sha256File,
		"digest content as AES key from a file")
	options = append(options, shaft.Provide(
		func() ([]cipher.AEAD, error) {
			if aes256Sha256File != "" {
				data, err := ioutil.ReadFile(aes256Sha256File)
				if err != nil {
					return nil, err
				}
				digest := sha256.Sum256(data)
				block, err := aes.NewCipher(digest[:])
				if err != nil {
					return nil, err
				}
				aead, err := cipher.NewGCM(block)
				if err != nil {
					return nil, err
				}
				return []cipher.AEAD{aead}, nil
			}
			return nil, nil
		}))
}
