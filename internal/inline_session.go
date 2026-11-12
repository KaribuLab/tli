package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

type InlineSession struct {
	Terminal           InlineTerminal
	Service            MenuService
	Setup              func(context.Context) error
	Options            ScanOptions
	Identity           RepositoryIdentity
	IdentityError      error
	Caps               TerminalOptions
	Ticks, ResizeTicks <-chan time.Time
	Now                func() time.Time
	Final              InlineModel
}
type inlineKeyResult struct {
	key string
	err error
}

func inlineControl(key string) string {
	switch key {
	case "ctrl+c", "eof", "esc":
		return key
	}
	return ""
}
func mergeInlineControl(a, b string) string {
	for _, key := range []string{"ctrl+c", "eof", "esc"} {
		if a == key || b == key {
			return key
		}
	}
	return ""
}
func (s *InlineSession) Run(ctx context.Context) (err error) {
	if s.Terminal == nil || s.Service == nil {
		return errors.New("sesión inline no configurada")
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	w, h, e := s.Terminal.Size()
	if e != nil {
		return e
	}
	model := NewInlineModel(s.Options, s.Identity, s.IdentityError, w, h)
	model, _ = UpdateInline(model, InlineEvent{Kind: "geometry-ready", Width: w, Height: h})
	if e = s.Terminal.Begin(); e != nil {
		return errors.Join(e, s.Terminal.End())
	}
	seenResize := s.Terminal.ResizeEpoch()
	tx := Transcript{Terminal: s.Terminal}
	healthy := true
	welcomeActive := false
	commit := func(key, text string) error {
		e := tx.CommitOnce(key, text)
		if e != nil {
			healthy = false
		}
		return e
	}
	ensureWelcome := func() error {
		if model.WelcomeCommitted {
			return nil
		}
		if e := commit("welcome", RenderInlineWelcome(s.Identity, s.IdentityError, s.Caps)); e != nil {
			return e
		}
		model.WelcomeCommitted = true
		welcomeActive = false
		return nil
	}
	keys := make(chan inlineKeyResult, 1)
	completion := make(chan InlineEvent, 1)
	progress := make(chan InlineEvent, 1)
	var readerCancel, jobCancel context.CancelFunc
	var readerDone, jobDone chan struct{}
	var jobRevision uint64
	var started time.Time
	stopReader := func(drain bool) string {
		if readerCancel != nil {
			readerCancel()
			<-readerDone
			readerCancel = nil
			readerDone = nil
		}
		if drain {
			select {
			case key := <-keys:
				if key.err == io.EOF {
					return "eof"
				}
				return inlineControl(key.key)
			default:
			}
		}
		return ""
	}
	startReader := func() {
		if readerDone != nil {
			return
		}
		readCtx, cancel := context.WithCancel(ctx)
		readerCancel = cancel
		done := make(chan struct{})
		readerDone = done
		go func() { defer close(done); k, e := s.Terminal.ReadKey(readCtx); keys <- inlineKeyResult{k, e} }()
	}
	defer func() {
		stopReader(true)
		if jobCancel != nil {
			jobCancel()
			<-jobDone
			event := <-completion
			if event.Result != nil {
				r := *event.Result
				model.Result = &r
			}
			model.LastError = event.Err
			select {
			case p := <-progress:
				if p.Revision == jobRevision {
					model.Progress = p.Progress
				}
			default:
			}
			if model.Result == nil {
				model.Result = &StatusResult{ScanID: model.Progress.ScanID}
			} else if model.Result.ScanID == "" {
				model.Result.ScanID = model.Progress.ScanID
			}
			if healthy && event.Kind == "scan-done" {
				err = errors.Join(err, commit(fmt.Sprintf("%d:outcome", event.Revision), RenderInlineOutcome(*model.Result, event.Err, s.Caps)))
			}
		}
		if healthy {
			err = errors.Join(err, ensureWelcome())
		}
		model.Busy = false
		s.Final = model
		err = errors.Join(err, s.Terminal.End())
		if !healthy && model.Result != nil && model.Result.ScanID != "" {
			err = errors.Join(err, fmt.Errorf("scan_id: %s; la tarea remota puede continuar", SafeTerminalText(model.Result.ScanID)))
		}
	}()
	pending := false
	pendingW, pendingH := w, h
	var resizedAt time.Time
	resize := func(width, height int) error {
		if !pending {
			if e := s.Terminal.AbandonActive("Vista anterior anulada por cambio de tamaño; revisa otra vez."); e != nil {
				healthy = false
				return e
			}
			if welcomeActive {
				tx.keepExisting("welcome")
				model.WelcomeCommitted = true
				welcomeActive = false
			}
		}
		seenResize = s.Terminal.ResizeEpoch()
		resizedAt = s.Now()
		pending = true
		pendingW = width
		pendingH = height
		model, _ = UpdateInline(model, InlineEvent{Kind: "resize", Width: width, Height: height})
		return nil
	}
	draw := func() error {
		f := RenderInlineActive(model, s.Caps)
		if !model.WelcomeCommitted && !f.WelcomeInActive {
			if e := ensureWelcome(); e != nil {
				return e
			}
			f = RenderInlineActive(model, s.Caps)
		}
		if e := s.Terminal.DrawActive(f); e != nil {
			if errors.Is(e, ErrInlineGeometry) {
				w, h, e := s.Terminal.Size()
				if e != nil {
					return e
				}
				return resize(w, h)
			}
			healthy = false
			return e
		}
		welcomeActive = f.WelcomeInActive
		return nil
	}
	ticks, resizeTicks := s.Ticks, s.ResizeTicks
	if ticks == nil && s.Caps.Animate {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		ticks = t.C
	}
	if resizeTicks == nil {
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		resizeTicks = t.C
	}
	if e = draw(); e != nil {
		return e
	}
	startJob := func(effect InlineEffect) {
		jobCtx, cancel := context.WithCancel(ctx)
		jobCancel = cancel
		done := make(chan struct{})
		jobDone = done
		jobRevision = effect.Revision
		started = s.Now()
		go func() {
			defer close(done)
			event := InlineEvent{Revision: effect.Revision}
			if effect.Kind == "preview" {
				p, e := s.Service.Preview(jobCtx, effect.Options)
				event.Kind = "preview-done"
				event.Plan = &p
				event.Err = e
			} else {
				sink := func(p ProgressEvent) {
					if jobCtx.Err() != nil {
						return
					}
					event := InlineEvent{Kind: "progress", Revision: effect.Revision, Progress: p}
					select {
					case progress <- event:
					default:
						select {
						case <-progress:
						default:
						}
						select {
						case progress <- event:
						default:
						}
					}
				}
				r, e := s.Service.Scan(jobCtx, effect.Options, effect.Fingerprint, sink)
				event.Kind = "scan-done"
				event.Result = &r
				event.Err = e
			}
			completion <- event
		}()
	}
	for {
		startReader()
		var event InlineEvent
		repaint := true
		select {
		case <-ctx.Done():
			return ctx.Err()
		case key := <-keys:
			stopReader(false)
			if key.err != nil {
				if key.err == io.EOF {
					return nil
				}
				return key.err
			}
			if key.key == "eof" {
				return nil
			}
			if key.key == "enter" {
				width, height, e := s.Terminal.Size()
				if e != nil {
					return e
				}
				if s.Terminal.ResizeEpoch() != seenResize || width != model.Width || height != model.Height {
					if e = resize(width, height); e != nil {
						return e
					}
					if e = draw(); e != nil {
						return e
					}
					continue
				}
			}
			if pending && key.key != "ctrl+c" && key.key != "esc" {
				continue
			}
			event = InlineEvent{Kind: "key", Key: key.key}
		case event = <-completion:
			if jobDone != nil {
				<-jobDone
				jobCancel()
				jobCancel = nil
				jobDone = nil
			}
		case event = <-progress:
			repaint = event.Revision == model.Revision && (event.Progress.Phase != model.Progress.Phase || event.Progress.ScanID != model.Progress.ScanID)
		case _, ok := <-resizeTicks:
			if !ok {
				resizeTicks = nil
				continue
			}
			width, height, e := s.Terminal.Size()
			if e != nil {
				return e
			}
			if s.Terminal.ResizeEpoch() != seenResize || width != model.Width || height != model.Height {
				if e = resize(width, height); e != nil {
					return e
				}
				if e = draw(); e != nil {
					return e
				}
				continue
			}
			if pending && s.Now().Sub(resizedAt) >= 200*time.Millisecond {
				queued := stopReader(true)
				drained, drainErr := s.Terminal.DiscardInput(ctx)
				if drainErr != nil {
					return drainErr
				}
				control := mergeInlineControl(queued, drained)
				if control == "eof" {
					return nil
				}
				if control != "" {
					pending = false
					model, _ = UpdateInline(model, InlineEvent{Kind: "geometry-ready", Width: pendingW, Height: pendingH})
					event = InlineEvent{Kind: "key", Key: control}
				} else {
					pending = false
					event = InlineEvent{Kind: "geometry-ready", Width: pendingW, Height: pendingH}
				}
			} else {
				continue
			}
		case _, ok := <-ticks:
			if !ok {
				ticks = nil
				continue
			}
			if !s.Caps.Animate || pending || (!welcomeActive && model.Stage != "running") {
				continue
			}
			event = InlineEvent{Kind: "tick", Elapsed: s.Now().Sub(started)}
		}
		var effect InlineEffect
		model, effect = UpdateInline(model, event)
		if event.Kind == "preview-done" {
			if event.Err != nil {
				if e = commit(fmt.Sprintf("%d:preview", event.Revision), inlineLiteral(s.Caps, "No se pudo preparar el preview: ")+SafeTerminalText(event.Err.Error())); e != nil {
					return e
				}
			} else if event.Plan != nil {
				if e = commit(fmt.Sprintf("%d:preview", event.Revision), RenderInlinePreview(*event.Plan, s.Caps)); e != nil {
					return e
				}
			}
		}
		if event.Kind == "scan-done" {
			r := StatusResult{}
			if model.Result != nil {
				r = *model.Result
			} else if event.Result != nil {
				r = *event.Result
			}
			if e = commit(fmt.Sprintf("%d:outcome", event.Revision), RenderInlineOutcome(r, event.Err, s.Caps)); e != nil {
				return e
			}
		}
		if model.Stage != "actions" && !model.WelcomeCommitted {
			if e = ensureWelcome(); e != nil {
				return e
			}
		}
		switch effect.Kind {
		case "preview", "scan":
			if e = ensureWelcome(); e != nil {
				return e
			}
			if effect.Kind == "preview" {
				e = commit(fmt.Sprintf("%d:action", effect.Revision), RenderInlineAction(model, s.Caps))
			} else {
				e = commit(fmt.Sprintf("%d:consent", effect.Revision), inlineLiteral(s.Caps, "> Envío a Titvo confirmado."))
			}
			if e != nil {
				return e
			}
			if jobDone == nil {
				startJob(effect)
			}
		case "cancel":
			if jobCancel != nil {
				jobCancel()
			}
		case "exit":
			if model.Interrupted {
				return context.Canceled
			}
			return nil
		case "setup":
			if e = ensureWelcome(); e != nil {
				return e
			}
			stopReader(true)
			if e = s.Terminal.CommitBlock(inlineLiteral(s.Caps, "> Configurar conexión")); e != nil {
				return e
			}
			if e = s.Terminal.End(); e != nil {
				return e
			}
			var setupErr error
			if s.Setup != nil {
				setupErr = s.Setup(ctx)
			}
			if errors.Is(setupErr, context.Canceled) || ctx.Err() != nil {
				return context.Canceled
			}
			if e = s.Terminal.Begin(); e != nil {
				return e
			}
			model, _ = UpdateInline(model, InlineEvent{Kind: "setup-done", Revision: effect.Revision, Err: setupErr})
			message := inlineLiteral(s.Caps, "Configuración guardada.")
			if setupErr != nil {
				message = inlineLiteral(s.Caps, "No se pudo configurar: ") + SafeTerminalText(setupErr.Error())
			}
			if e = commit(fmt.Sprintf("%d:setup", effect.Revision), message); e != nil {
				return e
			}
		}
		if repaint {
			if e = draw(); e != nil {
				return e
			}
		}
	}
}
