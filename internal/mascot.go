package internal

import (
	"fmt"
	"io"
)

var robotFrames = [4][4]string{
	{" ▄▟██▙▄", " ▐ ▪▪ ▌", "  ▀██▀", "  ▘  ▝"},
	{" ▄▟██▙▄", " ▐ ▪▪ ▌", "  ▀██▀", " ▝  ▘ "},
	{" ▄▟██▙▄", " ▐ ── ▌", "  ▀██▀", "  ▘  ▝"},
	{" ▄▟██▙▄", " ▐ ▪▪ ▌", "  ▀██▀", " ▝  ▘ "},
}

func WriteMascot(out io.Writer, o TerminalOptions, frame int) error {
	if !o.Interactive {
		return nil
	}
	if frame < 0 {
		frame = 0
	}
	lines := robotFrames[frame%len(robotFrames)]
	if o.ASCII {
		lines = [4]string{" .----.", " |o  o|", " '----'", "  /  \\"}
	}
	messages := [4]string{"TITVO", "Seguridad para tu código", "Revisa antes de subir", ""}
	if o.ASCII {
		messages[1] = "Seguridad para tu codigo"
	}
	for i, line := range lines {
		start, end := "", ""
		if o.Color {
			start = "\x1b[36m"
			end = "\x1b[0m"
		}
		if _, e := fmt.Fprintf(out, "%s%s%s  %s\n", start, line, end, messages[i]); e != nil {
			return e
		}
	}
	return nil
}
