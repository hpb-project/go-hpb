package example

import (
	"fmt"
	"testing"
)

func TestNewExampleModule(t *testing.T) {
	em := NewExampleModule(nil)
	if em == nil {
		fmt.Errorf("NewExampleModule failed.\n")
	}
}
