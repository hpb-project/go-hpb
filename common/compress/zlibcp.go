package compress

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"io"
)

//const (
//	NoCompression = 0
//	BestSpeed     = 1
//
//	BestCompression    = 9
//	DefaultCompression = -1
//)
//
const (
	NoCompression      = flate.NoCompression
	BestSpeed          = flate.BestSpeed
	BestCompression    = flate.BestCompression
	DefaultCompression = flate.DefaultCompression
)

//compress with zlib
func ZlibCompress(src []byte, level int) ([]byte, error) {
	var in bytes.Buffer
	w, err := zlib.NewWriterLevel(&in, level)
	w.Write(src)
	w.Close()
	return in.Bytes(), err
}

//uncompress with zlib
func ZlibUnCompress(compressSrc []byte) []byte {
	b := bytes.NewReader(compressSrc)
	var out bytes.Buffer
	r, _ := zlib.NewReader(b)
	io.Copy(&out, r)
	return out.Bytes()
}
