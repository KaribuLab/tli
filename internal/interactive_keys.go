package internal

import (
	"context"
	"errors"
	"io"
	"os"
	"time"
	"unicode/utf8"
)

func panelReadByte(ctx context.Context, in io.Reader) (byte, error) {
	if e := ctx.Err(); e != nil {
		return 0, e
	}
	var b [1]byte
	var n int
	var e error
	if f, ok := in.(*os.File); ok {
		n, e = readFileByte(ctx, f, b[:])
	} else {
		n, e = in.Read(b[:])
	}
	if n == 1 {
		return b[0], nil
	}
	if e == nil {
		e = io.ErrNoProgress
	}
	return 0, e
}
func ReadInteractiveKey(ctx context.Context, in io.Reader) (string, error) {
	b, e := panelReadByte(ctx, in)
	if e != nil {
		return "", e
	}
	switch b {
	case 3:
		return "ctrl+c", nil
	case 4:
		return "eof", nil
	case '\r', '\n':
		return "enter", nil
	case '\t':
		return "tab", nil
	case 8, 127:
		return "backspace", nil
	case 27:
		seqCtx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		defer cancel()
		next, e := panelReadByte(seqCtx, in)
		if errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled) || e == io.EOF {
			return "esc", nil
		}
		if e != nil {
			return "", e
		}
		if next != '[' && next != 'O' {
			return "esc", nil
		}
		sequence := ""
		for i := 0; i < 12; i++ {
			part, e := panelReadByte(seqCtx, in)
			if errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled) || e == io.EOF {
				return "esc", nil
			}
			if e != nil {
				return "", e
			}
			sequence += string(part)
			if part >= 0x40 && part <= 0x7e {
				break
			}
		}
		switch sequence {
		case "A":
			return "up", nil
		case "B":
			return "down", nil
		case "C":
			return "right", nil
		case "D":
			return "left", nil
		case "5~":
			return "pageup", nil
		case "6~":
			return "pagedown", nil
		}
		return "unknown", nil
	}
	if b < 32 {
		return "unknown", nil
	}
	data := []byte{b}
	for !utf8.FullRune(data) && len(data) < utf8.UTFMax {
		part, e := panelReadByte(ctx, in)
		if e != nil {
			return "", e
		}
		data = append(data, part)
	}
	if !utf8.Valid(data) {
		return "unknown", nil
	}
	return string(data), nil
}
