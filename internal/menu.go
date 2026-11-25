package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type MenuService interface {
	Preview(context.Context, ScanOptions) (ScanPlan, error)
	Scan(context.Context, ScanOptions, string, ProgressSink) (StatusResult, error)
}
type Menu struct {
	In       io.Reader
	Out, Err io.Writer
	Terminal TerminalOptions
	Service  MenuService
	Setup    func(context.Context) error
	Defaults ScanOptions
}

// Read a line without buffering ahead into the password/setup input.
func readInputLine(ctx context.Context, in io.Reader) (string, error) {
	value, e := readInputValue(ctx, in, false)
	return strings.TrimSpace(value), e
}
func readInputValue(ctx context.Context, in io.Reader, raw bool) (string, error) {
	var value []byte
	var c [1]byte
	for {
		if e := ctx.Err(); e != nil {
			return "", e
		}
		var n int
		var e error
		if file, ok := in.(*os.File); ok {
			n, e = readFileByte(ctx, file, c[:])
		} else {
			n, e = in.Read(c[:])
		}
		if n > 0 {
			if c[0] == 3 {
				return "", context.Canceled
			}
			if c[0] == '\n' || (raw && c[0] == '\r') {
				return string(value), nil
			}
			if raw && (c[0] == 127 || c[0] == 8) {
				if len(value) > 0 {
					_, size := utf8.DecodeLastRune(value)
					value = value[:len(value)-size]
				}
				continue
			}
			if len(value) >= 4096 {
				return "", fmt.Errorf("entrada demasiado larga")
			}
			value = append(value, c[0])
		}
		if e != nil {
			if e == io.EOF && len(value) > 0 {
				return string(value), nil
			}
			return "", e
		}
		if n == 0 {
			return "", io.ErrNoProgress
		}
	}
}
func (m Menu) Run(ctx context.Context) error {
	if !m.Terminal.Interactive {
		return nil
	}
	in, inOK := m.In.(*os.File)
	out, outOK := m.Out.(*os.File)
	if inOK && outOK && inlinePlatformSupported() && DetectTerminal(in, out, os.Getenv).Interactive {
		terminal := NewInlineTerminal(in, out, m.Terminal)
		w, h, e := terminal.Size()
		if e == nil && w >= 40 && h >= 10 {
			id, identityErr := (GitSource{}).Identity(ctx, m.Defaults)
			session := InlineSession{Terminal: terminal, Service: m.Service, Setup: m.Setup, Options: m.Defaults, Identity: id, IdentityError: identityErr, Caps: m.Terminal}
			return session.Run(ctx)
		}
	}
	return m.runNumeric(ctx)
}
func (m Menu) runNumeric(ctx context.Context) error {
	if !m.Terminal.Interactive {
		return nil
	}
	if m.In == nil || m.Out == nil || m.Err == nil || m.Service == nil {
		return fmt.Errorf("menú no configurado")
	}
	if e := WriteMascot(m.Out, m.Terminal, 0); e != nil {
		return e
	}
	for {
		fmt.Fprintln(m.Out, "\n1. Escanear\n2. Previsualizar archivos\n3. Configurar conexión\n4. Salir")
		choice, e := readInputLine(ctx, m.In)
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		switch choice {
		case "4":
			return nil
		case "3":
			if m.Setup != nil {
				if e = m.Setup(ctx); e != nil {
					if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
						return e
					}
					fmt.Fprintln(m.Err, e)
				}
			}
		case "1", "2":
			o := m.Defaults
			fmt.Fprintln(m.Out, "1. Completo\n2. Commit\n3. Staged\n0. Volver")
			scope, e := readInputLine(ctx, m.In)
			if e == io.EOF {
				return nil
			}
			if e != nil {
				return e
			}
			switch scope {
			case "1":
				o.Scope = ScopeFull
				o.Commit = ""
			case "2":
				o.Scope = ScopeCommit
				fmt.Fprintln(m.Out, "Commit [HEAD]:")
				o.Commit, e = readInputLine(ctx, m.In)
				if e == io.EOF {
					return nil
				}
				if e != nil {
					return e
				}
				if o.Commit == "" {
					o.Commit = "HEAD"
				}
			case "3":
				o.Scope = ScopeStaged
				o.Commit = ""
			case "0":
				continue
			default:
				fmt.Fprintln(m.Err, "Selecciona un alcance válido")
				continue
			}
			for {
				plan, e := m.Service.Preview(ctx, o)
				if e != nil {
					fmt.Fprintln(m.Err, e)
					break
				}
				if e = WritePlan(m.Out, plan, "markdown"); e != nil {
					return e
				}
				if choice == "2" {
					break
				}
				fmt.Fprintln(m.Out, "¿Subir estos archivos a Titvo e iniciar el análisis? [s/N]")
				answer, e := readInputLine(ctx, m.In)
				if e == io.EOF {
					return nil
				}
				if e != nil {
					return e
				}
				if !affirmative(answer) {
					break
				}
				var tick <-chan time.Time
				var ticker *time.Ticker
				if m.Terminal.Animate {
					ticker = time.NewTicker(500 * time.Millisecond)
					tick = ticker.C
				}
				sink, finish := progressSession(ctx, m.Err, m.Terminal, tick, time.Now)
				result, scanErr := m.Service.Scan(ctx, o, plan.Fingerprint, sink)
				finish()
				if ticker != nil {
					ticker.Stop()
				}
				if result.ScanID != "" {
					if e = WriteResult(m.Out, result, "markdown", false); e != nil {
						return e
					}
				}
				if scanErr == nil {
					break
				}
				if result.ScanID != "" {
					fmt.Fprintf(m.Err, "Escaneo: %s. La tarea remota puede continuar; no se ha solicitado cancelación remota.\n", result.ScanID)
				}
				if errors.Is(scanErr, context.Canceled) || errors.Is(scanErr, context.DeadlineExceeded) {
					return scanErr
				}
				var typed *ScanError
				if errors.As(scanErr, &typed) && typed.Kind == "plan-changed" {
					fmt.Fprintln(m.Err, "Los archivos cambiaron. Revisa y confirma un nuevo preview.")
					continue
				}
				if errors.Is(scanErr, ErrCredentials) {
					fmt.Fprintln(m.Out, "Faltan credenciales. ¿Deseas configurar la conexión? [s/N]")
					answer, e = readInputLine(ctx, m.In)
					if e == io.EOF {
						return nil
					}
					if e != nil {
						return e
					}
					if affirmative(answer) && m.Setup != nil {
						if e = m.Setup(ctx); e != nil {
							if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
								return e
							}
							fmt.Fprintln(m.Err, e)
						}
					}
				} else {
					fmt.Fprintln(m.Err, scanErr)
				}
				break
			}
		default:
			fmt.Fprintln(m.Err, "Selecciona una opción válida")
		}
	}
}
func affirmative(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "s", "si", "sí":
		return true
	default:
		return false
	}
}
func progressSession(ctx context.Context, out io.Writer, o TerminalOptions, ticks <-chan time.Time, now func() time.Time) (ProgressSink, func()) {
	o = progressDestination(out, o)
	if !o.Animate {
		ticks = nil
	}
	var mu sync.Mutex
	last := ProgressEvent{}
	started := now()
	closed := false
	sink := func(p ProgressEvent) {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			return
		}
		if p.Files == 0 {
			p.Files = last.Files
			p.Bytes = last.Bytes
		}
		last = p
		last.Elapsed = now().Sub(started)
		WriteProgress(out, o, last)
	}
	stop, done := make(chan struct{}), make(chan struct{})
	if ticks != nil {
		go func() {
			defer close(done)
			for {
				select {
				case <-ctx.Done():
					return
				case <-stop:
					return
				case _, ok := <-ticks:
					if !ok {
						return
					}
					mu.Lock()
					if last.Phase != "" && !closed {
						last.Elapsed = now().Sub(started)
						WriteProgress(out, o, last)
					}
					mu.Unlock()
				}
			}
		}()
	} else {
		close(done)
	}
	var once sync.Once
	finish := func() {
		once.Do(func() {
			close(stop)
			<-done
			mu.Lock()
			defer mu.Unlock()
			closed = true
			if o.Animate {
				fmt.Fprint(out, "\r\x1b[2K")
			}
		})
	}
	return sink, finish
}
