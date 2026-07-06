package prompt

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// SecretPrompter reads secret values from a user.
type SecretPrompter interface {
	ReadSecret(label string) ([]byte, error)
}

// TerminalPrompter reads secrets from a terminal without echo when possible.
type TerminalPrompter struct {
	In  io.Reader
	Out io.Writer
}

// NewTerminalPrompter creates a terminal prompter backed by stdin/stderr.
func NewTerminalPrompter() TerminalPrompter {
	return TerminalPrompter{In: os.Stdin, Out: os.Stderr}
}

// ReadSecret reads a secret value. If the input is not a terminal, it reads one line.
func (p TerminalPrompter) ReadSecret(label string) ([]byte, error) {
	out := p.Out
	if out == nil {
		out = io.Discard
	}
	in := p.In
	if in == nil {
		in = os.Stdin
	}

	if label == "" {
		label = "Secret"
	}
	_, _ = fmt.Fprintf(out, "%s: ", label)

	if file, ok := in.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		value, err := term.ReadPassword(int(file.Fd()))
		_, _ = fmt.Fprintln(out)
		if err != nil {
			return nil, fmt.Errorf("read secret: %w", err)
		}
		return bytesTrimSpace(value), nil
	}

	line, err := readLine(in)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read secret: %w", err)
	}
	return []byte(strings.TrimSpace(line)), nil
}

func readLine(in io.Reader) (string, error) {
	var builder strings.Builder
	var buffer [1]byte

	for {
		n, err := in.Read(buffer[:])
		if n > 0 {
			if buffer[0] == '\n' {
				return builder.String(), nil
			}
			builder.WriteByte(buffer[0])
		}
		if err != nil {
			return builder.String(), err
		}
	}
}

func bytesTrimSpace(value []byte) []byte {
	return []byte(strings.TrimSpace(string(value)))
}
