//go:build windows

package logging

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

const enableVirtualTerminalProcessing = 0x0004

func colorEnabled(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}

	fd := int(f.Fd())
	if !term.IsTerminal(fd) {
		return false
	}

	handle := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	if mode&enableVirtualTerminalProcessing != 0 {
		return true
	}
	if err := windows.SetConsoleMode(handle, mode|enableVirtualTerminalProcessing); err != nil {
		return false
	}
	return true
}
