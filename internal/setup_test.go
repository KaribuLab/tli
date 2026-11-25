package internal

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestSetupReturnsErrorWithoutExiting(t *testing.T) {
	if os.Getenv("TLI_SETUP_HELPER") == "1" {
		cmd := NewSetupCommand()
		cmd.SetArgs(nil)
		cmd.SetIn(os.Stdin)
		if e := cmd.Execute(); e == nil {
			t.Fatal("invalid endpoint accepted")
		}
		os.Stdout.WriteString("returned-safely\n")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSetupReturnsErrorWithoutExiting$")
	cmd.Env = append(os.Environ(), "TLI_SETUP_HELPER=1")
	cmd.Stdin = strings.NewReader("http://unsafe.test\n")
	out, e := cmd.CombinedOutput()
	if e != nil || !strings.Contains(string(out), "returned-safely") {
		t.Fatalf("setup terminated process: err=%v output=%s", e, out)
	}
}
