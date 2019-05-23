package compress

import (
	"bytes"
	"testing"
)

//compress and uncompress test together in method TestZlibCompress
func TestZlibCompress(t *testing.T) {
	tests := []struct {
		original   string
		level      int
		dealResult bool
	}{
		{"1234567890abcdefg1234567890abcdefg1234567890abcdefg", 0, true},
		{"1234567890abcdefg1234567890abcdefg1234567890abcdefg", 1, true},
		{"1234567890abcdefg1234567890abcdefg1234567890abcdefgggggggggggggggggggggggggggg", 5, true},
		{"1234567890abcdefg1234567890abcdefg1234567890abcdefg", 9, true},
		{"1234567890abcdefg1234567890abcdefg1234567890abcdefg", -1, true},

		{"!@#$%^&*()_+{}|:", 0, true},
		{"!@#$%^&*()_+{}|:", 1, true},
		{"!@#$%^&*()_+{}|:", 5, true},
		{"!@#$%^&*()_+{}|:", 9, true},
		{"!@#$%^&*()_+{}|:", -1, true},

		{"", -1, true},
	}

	for _, tt := range tests {
		o, err := ZlibCompress([]byte(tt.original), tt.level)
		if err != nil {
			t.Error(err)
		}
		t.Log("compress result length:", len(o), o)
		t.Log("compress result :", string(o))
		p := ZlibUnCompress(o)
		t.Log("uncompress result length:", len(p), string(p[:]))
		if bytes.Compare([]byte(tt.original), p) != 0 {
			t.Error("uncompress failed")
		} else {
			t.Log("compress and uncompress success")
		}
	}
}
