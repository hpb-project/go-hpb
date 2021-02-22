package types

import (
	"strings"
	"testing"
)

func TestNewExtraDetail(t *testing.T) {
	extra, err := NewExtraDetail(0)
	if err != nil {
		t.Fatal("newExtraDetail failed")
	}

	var vanitydata = "hahaha"
	copy(extra.Vanity[:], []byte(vanitydata))
	vanity := extra.GetVanity()
	if strings.Compare(string(vanity), vanitydata) != 0 {
		t.Fatal("compare vanity failed")
	}
}
