package prompt

import (
	"bytes"
	"testing"
)

func TestTerminalPrompterReadsLineFromNonTerminal(t *testing.T) {
	var out bytes.Buffer
	prompter := TerminalPrompter{
		In:  bytes.NewBufferString("secret\n"),
		Out: &out,
	}

	secret, err := prompter.ReadSecret("Master password")
	if err != nil {
		t.Fatalf("ReadSecret returned error: %v", err)
	}
	if string(secret) != "secret" {
		t.Fatalf("secret = %q, want secret", string(secret))
	}
	if out.String() != "Master password: " {
		t.Fatalf("prompt = %q, want label", out.String())
	}
}

func TestTerminalPrompterReadsMultipleLinesFromNonTerminal(t *testing.T) {
	var out bytes.Buffer
	in := bytes.NewBufferString("password\nmaster\n")
	prompter := TerminalPrompter{
		In:  in,
		Out: &out,
	}

	first, err := prompter.ReadSecret("Password")
	if err != nil {
		t.Fatalf("first ReadSecret returned error: %v", err)
	}
	second, err := prompter.ReadSecret("Master password")
	if err != nil {
		t.Fatalf("second ReadSecret returned error: %v", err)
	}

	if string(first) != "password" {
		t.Fatalf("first secret = %q, want password", string(first))
	}
	if string(second) != "master" {
		t.Fatalf("second secret = %q, want master", string(second))
	}
	if out.String() != "Password: Master password: " {
		t.Fatalf("prompt = %q, want both labels", out.String())
	}
}
