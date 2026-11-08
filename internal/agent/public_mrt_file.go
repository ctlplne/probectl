// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"io"
	"os"
)

type publicMRTFile struct {
	io.Reader
	file *os.File
	gzip *gzip.Reader
}

func (source *publicMRTFile) Close() error {
	var err error
	if source.gzip != nil {
		err = source.gzip.Close()
	}
	return errors.Join(err, source.file.Close())
}

// OpenPublicMRTFile opens only a local regular file. Gzip/bzip2 are detected
// from original bytes, not its filename; their checksum/truncation failures
// propagate to the importer and cannot masquerade as whole-source EOF.
func OpenPublicMRTFile(path string) (io.ReadCloser, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.Join(err, errors.New("public MRT input must be a regular local file"))
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.Join(err, errors.New("public MRT input must be a regular local file"))
	}
	buffer := bufio.NewReader(file)
	magic, err := buffer.Peek(3)
	if err != nil && !errors.Is(err, io.EOF) {
		_ = file.Close()
		return nil, err
	}
	out := &publicMRTFile{Reader: buffer, file: file}
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		out.gzip, err = gzip.NewReader(buffer)
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		out.Reader = out.gzip
	case bytes.Equal(magic, []byte("BZh")):
		out.Reader = bzip2.NewReader(buffer)
	}
	return out, nil
}
