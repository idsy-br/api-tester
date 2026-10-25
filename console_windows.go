package main

import "golang.org/x/sys/windows"

// O console antigo do Windows (conhost) só entende os códigos de cor e de limpar
// linha da barra de progresso com o modo de terminal virtual ligado.
func init() {
	for _, h := range []windows.Handle{windows.Stdout, windows.Stderr} {
		var mode uint32
		if windows.GetConsoleMode(h, &mode) == nil {
			_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
		}
	}
}
