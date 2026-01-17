package main

import (
	"os"
	"testing"
)

func TestMain_Help(t *testing.T) {
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })

	os.Args = []string{"wiretap", "--help"}
	main()
}
