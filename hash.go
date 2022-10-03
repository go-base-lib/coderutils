package coderutils

import (
	"bytes"
	"github.com/go-base-lib/goextension"
	"hash"
	"io"
	"os"
)

func Hash(h hash.Hash, b []byte) (goextension.Bytes, error) {
	return HashByReader(h, bytes.NewReader(b))
}

func HashByFilePath(h hash.Hash, p string) (goextension.Bytes, error) {
	file, err := os.OpenFile(p, os.O_RDONLY, 0655)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return HashByReader(h, file)
}

func HashByReader(h hash.Hash, r io.Reader) (goextension.Bytes, error) {
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
