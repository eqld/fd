package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

type (
	hashT      [32]byte
	sizeT      int64
	signatureT struct {
		hash hashT
		size sizeT
	}
	catalogT map[signatureT][]string
)

func main() {

	// determine working path

	root, err := os.Getwd()
	if err != nil {
		log.Fatalln("fail to determine working path:", err)
	}
	log.Println("working path:", root)

	// create execution context

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// capture system signals

	go func() {
		defer cancel()

		signalC := make(chan os.Signal, 1)
		signal.Notify(signalC, syscall.SIGINT, syscall.SIGTERM)

		select {
		case <-ctx.Done():
		case signal := <-signalC:
			log.Printf("received system signal '%v', terminating\n", signal)
		}
	}()

	// walk the file tree to find duplicates

	catalog := make(catalogT)

	err = filepath.Walk(root, func(path string, fileInfo os.FileInfo, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// proceed
		}

		if fileInfo.IsDir() {
			log.Printf("processing '%s'...\n", path)
			return nil
		}

		// don't stuck on i/o operations

		type openResultT struct {
			file   *os.File
			err    error
			opened bool
		}
		openResultC := make(chan openResultT, 1)

		go func() {
			var openResult openResultT
			openResult.file, openResult.err = os.Open(path)
			openResult.opened = true
			select {
			case openResultC <- openResult:
			case <-ctx.Done():
				// close openResultC if the context was cancelled
				close(openResultC)
			}
		}()

		var openResult openResultT
		select {
		case openResult = <-openResultC:
			if !openResult.opened {
				// openResultC was closed due to context cancellation
				return ctx.Err()
			}
		case <-ctx.Done():
			return ctx.Err()
		}

		file, err := openResult.file, openResult.err
		if err != nil {
			log.Printf("unable to read the file '%s': %v\n", path, err)
			return nil
		}
		defer file.Close()

		sum := sha256.New()
		n, err := io.Copy(sum, file)
		if err != nil {
			log.Printf("fail to calculate hash sum of the file '%s': %v\n", path, err)
			return nil
		}
		if n != fileInfo.Size() {
			log.Printf("fail to read out the file '%s': read %d bytes out of %d\n", path, n, fileInfo.Size())
			return nil
		}

		var signature signatureT
		signature.size = sizeT(n)
		l := copy(signature.hash[:], sum.Sum(nil))
		if l != len(signature.hash) {
			return fmt.Errorf("wrong hash length: expected %d bytes, but got %d", len(signature.hash), l)
		}

		catalog[signature] = append(catalog[signature], path)
		return nil
	})
	if err != nil {
		log.Println("unable to continue execution:", err)
	}

	// print out the duplicates

	for signature, paths := range catalog {
		if len(paths) > 1 {
			fmt.Printf("%s\t%d\n", hex.EncodeToString(signature.hash[:]), signature.size)
			for i, path := range paths {
				fmt.Printf("\t%d\t%s\n", i, path)
			}
		}
	}
}
