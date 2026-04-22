//go:build !windows

package logging

import (
	"io"
	"os"

	"golang.org/x/term"
)

func colorEnabled(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}
