package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// promptSecret pergunta a senha sem mostrar o que se digita. No Windows só
// desliga o eco do console e lê pelo mesmo leitor das outras perguntas: o console
// cuida do backspace e o Go converte acentos (UTF-16) certo. O ReadPassword do
// x/term lê byte a byte, e senha com acento ou corrigida no backspace chegava
// diferente na API.
func promptSecret(label string) (string, error) {
	h := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil || stdin.Buffered() > 0 {
		return promptRaw(label)
	}
	if err := windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		return promptRaw(label)
	}
	defer windows.SetConsoleMode(h, mode)
	answer, err := promptRaw(label)
	fmt.Fprintln(os.Stderr)
	return answer, err
}

// promptRaw lê a linha sem tirar espaços: na senha eles contam.
func promptRaw(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("ler do terminal: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}
