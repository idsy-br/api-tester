//go:build !windows

package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// promptSecret pergunta a senha sem mostrar o que se digita.
func promptSecret(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) || stdin.Buffered() > 0 {
		return promptRaw(label)
	}
	fmt.Fprint(os.Stderr, label)
	raw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("ler a senha: %w", err)
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
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
