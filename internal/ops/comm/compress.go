package comm

import (
	"compress/gzip"
	"io"
)

// gzipDecompress implements Decompressor for decompressing gzip content.
func gzipDecompress(r io.Reader) io.Reader {
	gzipReader, _ := gzip.NewReader(r)

	pipeOut, pipeIn := io.Pipe()
	go func() {
		_, err := io.Copy(pipeIn, gzipReader)
		if err != nil {
			pipeIn.CloseWithError(err)
			gzipReader.Close()
			return
		}
		if err := gzipReader.Close(); err != nil {
			pipeIn.CloseWithError(err)
			return
		}
		pipeIn.Close()
	}()
	return pipeOut
}
