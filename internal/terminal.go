package internal

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

type TerminalOptions struct{ Interactive, Color, Animate, ASCII bool }

func envTrue(value string) bool {
	switch strings.ToLower(value) {
	case "", "false", "0", "no", "off":
		return false
	default:
		return true
	}
}
func terminalOptions(inTTY, outTTY bool, env func(string) string) TerminalOptions {
	interactive := inTTY && outTTY && !envTrue(env("CI")) && !envTrue(env("GITHUB_ACTIONS")) && env("BITBUCKET_BUILD_NUMBER") == "" && env("TERM") != "dumb"
	color := interactive && env("NO_COLOR") == ""
	return TerminalOptions{Interactive: interactive, Color: color, Animate: color && !envTrue(env("TLI_NO_ANIMATION")), ASCII: envTrue(env("TLI_ASCII"))}
}
func DetectTerminal(in, out *os.File, env func(string) string) TerminalOptions {
	if env == nil {
		env = os.Getenv
	}
	if in == nil || out == nil {
		return terminalOptions(false, false, env)
	}
	return terminalOptions(term.IsTerminal(int(in.Fd())), term.IsTerminal(int(out.Fd())), env)
}
func progressDestination(out io.Writer, o TerminalOptions) TerminalOptions {
	file, ok := out.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		o.Animate = false
		o.Color = false
	}
	return o
}
func WriteProgress(out io.Writer, o TerminalOptions, event ProgressEvent) error {
	o = progressDestination(out, o)
	if !o.Interactive {
		return nil
	}
	prefix, suffix := "", "\n"
	if o.Animate {
		prefix = "\r\x1b[2K"
		suffix = ""
	}
	phase := map[string]string{"preparing": "Preparando snapshot", "uploading": "Subiendo snapshot", "analyzing": "Analizando", "completed": "Finalizado"}[event.Phase]
	if phase == "" {
		phase = "Esperando estado"
	}
	face := robotFrames[int(event.Elapsed.Milliseconds()/500)%len(robotFrames)][1]
	if o.ASCII {
		face = "[o_o]"
	}
	_, e := fmt.Fprintf(out, "%s%s %s · %d archivos · %d bytes · %s · %s%s", prefix, face, phase, event.Files, event.Bytes, event.ScanID, event.Elapsed.Round(1e9), suffix)
	return e
}
