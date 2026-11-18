package gateway

import (
	"context"
	"fmt"
	"io"

	tea "charm.land/bubbletea/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"golang.org/x/crypto/ssh"

	"github.com/Azure/blip/internal/gateway/menu"
	"github.com/Azure/blip/internal/session"
	"github.com/Azure/blip/internal/wire"
)

// runInteractive keeps the SSH shell alive while menu and guest sessions take
// turns owning the terminal. Only quitting the menu sends an SSH exit status.
func (c *sessionChannel) runInteractive(ctx context.Context, req *ssh.Request) {
	defer c.ch.Close()
	if c.srv.Catalog == nil {
		fmt.Fprint(c.ch.Stderr(), "blip: state catalog is unavailable\r\n")
		req.Reply(false, nil)
		return
	}
	if err := req.Reply(true, nil); err != nil {
		return
	}
	input := newChannelInput(c.ch)
	defer input.close()
	selected, notice := c.sandbox, ""
	for ctx.Err() == nil {
		entry, err := c.showMenu(ctx, input, selected, notice)
		if err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(c.ch.Stderr(), "blip: %v\r\n", err)
			}
			return
		}
		if entry == nil {
			c.ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			c.ch.CloseWrite()
			return
		}
		selected, notice = entry.ID, ""
		fmt.Fprintf(c.ch, "Connecting to %s...\r\n", entry.Name)
		c.mu.Lock()
		o := c.open
		c.mu.Unlock()
		sess, err := c.srv.openState(ctx, c.owner, *entry, o)
		if err != nil {
			notice = err.Error()
			continue
		}
		notice = c.relayInteractive(ctx, input, sess, o)
	}
}

func (c *sessionChannel) showMenu(ctx context.Context, input *channelInput, selected, notice string) (*menu.Entry, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	reader := input.reader()
	defer reader.Close()
	stop := context.AfterFunc(ctx, func() { reader.Close() })
	defer stop()
	c.mu.Lock()
	o := c.open
	c.mu.Unlock()
	width, height := menuSize(o.Rows, o.Cols)
	m := menu.New(ctx, c.srv.menuBackend(c.owner), selected, width, height, notice)
	defer m.Close()
	p := tea.NewProgram(m,
		tea.WithInput(nil), tea.WithOutput(&crlfWriter{w: c.ch}), tea.WithContext(ctx),
		tea.WithEnvironment(o.Env), tea.WithWindowSize(width, height),
		tea.WithoutSignalHandler(),
		tea.WithFilter(func(_ tea.Model, msg tea.Msg) tea.Msg {
			if _, ok := msg.(tea.QuitMsg); ok {
				reader.Close()
			}
			if _, ok := msg.(tea.WindowSizeMsg); ok {
				// Bubble Tea's initial size is asynchronous: always use the
				// latest SSH size, even if an older event arrives last.
				c.mu.Lock()
				width, height := menuSize(c.open.Rows, c.open.Cols)
				c.mu.Unlock()
				return tea.WindowSizeMsg{Width: width, Height: height}
			}
			return msg
		}),
	)
	// Decode remote input separately so we can drain the decoder after Quit.
	// Its event sends are not cancelable; giving it the program's event channel
	// directly can strand a goroutine when several keys arrive with Enter/q.
	// WithInput(nil) also avoids terminal probes leaking into the next shell.
	events := make(chan uv.Event)
	inputDone := make(chan struct{})
	go func() {
		defer close(events)
		uv.NewTerminalReader(reader, terminalType(o.Env)).StreamEvents(ctx, events)
	}()
	go func() {
		defer close(inputDone)
		for event := range events {
			switch event := event.(type) {
			case uv.KeyPressEvent:
				p.Send(tea.KeyPressMsg(event))
			case uv.PasteEvent:
				p.Send(tea.PasteMsg(event))
			case uv.PasteStartEvent:
				p.Send(tea.PasteStartMsg(event))
			case uv.PasteEndEvent:
				p.Send(tea.PasteEndMsg(event))
			}
		}
		p.Send(tea.Quit())
	}()
	stopResize := c.forwardResizes(ctx, func(rows, cols uint16) {
		width, height := menuSize(rows, cols)
		p.Send(tea.WindowSizeMsg{Width: width, Height: height})
	})
	_, err := p.Run()
	cancel()
	reader.Close()
	<-inputDone
	stopResize()
	return m.Selected, err
}

func menuSize(rows, cols uint16) (width, height int) {
	width, height = int(cols), int(rows)
	if width == 0 {
		width = 80
	}
	if height == 0 {
		height = 24
	}
	return width, height
}

func terminalType(env []string) string {
	for i := len(env) - 1; i >= 0; i-- {
		if len(env[i]) >= 5 && env[i][:5] == "TERM=" {
			return env[i][5:]
		}
	}
	return "xterm"
}

func (c *sessionChannel) relayInteractive(ctx context.Context, input *channelInput, sess *session.Session, o wire.Open) string {
	c.mu.Lock()
	if c.closing || ctx.Err() != nil {
		c.mu.Unlock()
		hangupSession(sess)
		return ""
	}
	c.sess = sess
	c.mu.Unlock()
	stopResize := c.resizeGuest(ctx, sess, o)
	reader := input.reader()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := io.Copy(sess, reader); err == nil {
			sess.CloseStdin()
		}
	}()
	exit, err := sess.Copy(c.ch, c.ch.Stderr(), func(message string) {
		fmt.Fprintf(c.ch.Stderr(), "blip: %s\r\n", message)
	})
	// Revoke input before starting the next menu. Close also unblocks a stdin
	// write to a guest that stopped consuming input; join that copier first.
	reader.Close()
	sess.Close()
	stopResize()
	<-done
	c.mu.Lock()
	c.sess = nil
	c.mu.Unlock()
	if err != nil {
		return err.Error()
	}
	if exit.Signal != "" {
		return fmt.Sprintf("Shell exited on %s.", exit.Signal)
	}
	if exit.Code != 0 {
		return fmt.Sprintf("Shell exited with code %d.", exit.Code)
	}
	return ""
}
