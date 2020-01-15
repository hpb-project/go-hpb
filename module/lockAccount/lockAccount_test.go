package lockAccount

import (
	"fmt"
	"testing"
)

func TestNewLockAccountModule(t *testing.T) {
	em := NewLockAccountModule()
	if em == nil {
		fmt.Errorf("NewExampleModule failed.\n")
	}
}
