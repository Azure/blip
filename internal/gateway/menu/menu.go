// Package menu provides the SSH gateway's terminal menu. It performs no terminal
// I/O itself; callers supply the Bubble Tea program's input, output, and size.
package menu

import (
	"context"
	"strings"
	"sync"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

// Entry is a state available to the authenticated user. ID and Parent are full
// resource names, UID identifies this particular resource, and Name is its
// short display name. Parent is the state's copyFrom resource, when present.
type Entry struct {
	ID, UID, Name, Parent string
	Running               bool
}

// Backend supplies states and change notifications. Create creates a new state
// from the configured image. Notifications may be coalesced: each notification
// prompts a fresh List, with at most one List call in flight.
type Backend interface {
	List(context.Context) ([]Entry, error)
	Create(context.Context, string) (Entry, error)
	Delete(context.Context, Entry) error
	// ValidateName reports whether name may be created, without side effects.
	ValidateName(string) error
	Subscribe() (<-chan struct{}, func())
}

type mode uint8

const (
	browsing mode = iota
	creating
	confirming
	helping
)

type action uint8

const (
	noAction action = iota
	createAction
	deleteAction
)

// Model is the menu's Bubble Tea model. Selected is set only when the user
// connects, including after creating a state successfully. It is nil on quit.
// Call Close after Program.Run, including when Run returns an error.
type Model struct {
	Selected *Entry

	ctx         context.Context
	cancel      context.CancelFunc
	backend     Backend
	changes     <-chan struct{}
	unsubscribe func()
	closeOnce   sync.Once

	rows         []row
	cursor       int
	offset       int
	preselect    string
	owner        string
	width        int
	height       int
	mode         mode
	input        textinput.Model
	deleteTarget Entry
	busy         action
	loading      bool
	loaded       bool
	dirty        bool
	quitting     bool
	notice       string
	err          string
}

var _ tea.Model = (*Model)(nil)

// New subscribes before the first list so changes during initialization cannot
// be missed. selected is the full resource ID supplied by the SSH connection;
// owner is the authenticated name shown in the frame.
func New(ctx context.Context, backend Backend, selected string, width, height int, notice, owner string) *Model {
	ctx, cancel := context.WithCancel(ctx)
	changes, unsubscribe := backend.Subscribe()
	input := textinput.New()
	input.Prompt = "> "
	input.Placeholder = "my-blip"
	input.CharLimit = 63
	// Clipboard subprocesses read the gateway host's clipboard, not the SSH
	// client's. Bracketed paste still arrives as normal Bubble Tea input.
	input.KeyMap.Paste.SetEnabled(false)
	styles := input.Styles()
	styles.Cursor.Blink = false
	styles.Focused.Prompt = promptStyle
	styles.Blurred.Prompt = promptStyle
	input.SetStyles(styles)
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	m := &Model{
		ctx: ctx, cancel: cancel, backend: backend,
		changes: changes, unsubscribe: unsubscribe,
		preselect: selected, owner: owner, width: width, height: height,
		input: input, notice: notice,
	}
	m.resizeInput()
	return m
}

func (m *Model) resizeInput() {
	m.input.SetWidth(max(1, m.contentWidth()-6))
}

// Close cancels outstanding commands and releases the backend subscription.
// It is safe to call more than once, including after normal menu termination.
func (m *Model) Close() {
	m.closeOnce.Do(func() {
		m.cancel()
		if m.unsubscribe != nil {
			m.unsubscribe()
		}
	})
}

type listMsg struct {
	entries []Entry
	err     error
}

type changedMsg struct{}
type subscriptionClosedMsg struct{}

type createdMsg struct {
	entry Entry
	err   error
}

type deletedMsg struct{ err error }

func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.reload(), m.waitForChange())
}

func (m *Model) reload() tea.Cmd {
	if m.loading {
		m.dirty = true
		return nil
	}
	m.loading = true
	ctx, backend := m.ctx, m.backend
	return func() tea.Msg {
		entries, err := backend.List(ctx)
		return listMsg{entries: entries, err: err}
	}
}

func (m *Model) waitForChange() tea.Cmd {
	ctx, changes := m.ctx, m.changes
	return func() tea.Msg {
		select {
		case <-ctx.Done():
			return tea.Quit()
		case _, ok := <-changes:
			if !ok {
				return subscriptionClosedMsg{}
			}
			return changedMsg{}
		}
	}
}

// Update handles backend results and terminal events. All backend I/O runs in
// commands, never on the Bubble Tea event loop.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.quitting {
		return m, nil
	}
	// Keep the browse window stable while a dialog is open; re-clamping it
	// against the dialog's shorter content area would jump the list.
	defer func() {
		if m.mode == browsing && m.busy == noAction {
			m.ensureVisible()
		}
	}()
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = max(0, msg.Width), max(0, msg.Height)
		m.resizeInput()
	case changedMsg:
		return m, tea.Batch(m.reload(), m.waitForChange())
	case subscriptionClosedMsg:
		// A closed subscription must not become an infinite refresh loop. Keep
		// a context waiter so disconnecting still terminates the menu.
		m.changes = nil
		return m, m.waitForChange()
	case listMsg:
		m.loading = false
		if msg.err != nil {
			m.err = "Could not load blips: " + msg.err.Error()
		} else {
			m.replaceEntries(msg.entries)
			m.loaded = true
			// A successful refresh must not erase a mutation's error.
			if strings.HasPrefix(m.err, "Could not load blips: ") {
				m.err = ""
			}
		}
		if m.dirty {
			m.dirty = false
			return m, m.reload()
		}
	case createdMsg:
		m.busy = noAction
		if msg.err != nil {
			m.err = "Could not create blip: " + msg.err.Error()
			return m, m.input.Focus()
		}
		return m, m.connect(msg.entry)
	case deletedMsg:
		m.busy, m.mode = noAction, browsing
		if msg.err != nil {
			m.err = "Could not delete blip: " + msg.err.Error()
		} else {
			m.err, m.notice = "", ""
		}
		return m, m.reload()
	case tea.KeyPressMsg:
		key := msg.String()
		if key == "ctrl+c" || key == "ctrl+d" || (key == "q" && (m.mode != creating || m.busy != noAction)) {
			m.Selected = nil
			return m, m.quit()
		}
		if m.busy != noAction {
			return m, nil
		}
		switch m.mode {
		case creating:
			switch key {
			case "esc":
				m.mode, m.err = browsing, ""
				m.input.Blur()
				return m, nil
			case "enter":
				name := strings.TrimSpace(m.input.Value())
				if name == "" {
					m.err = "Enter a name for the new blip."
					return m, nil
				}
				if err := m.backend.ValidateName(name); err != nil {
					m.err = err.Error()
					return m, nil
				}
				m.err, m.notice, m.busy = "", "", createAction
				m.input.Blur()
				ctx, backend := m.ctx, m.backend
				return m, func() tea.Msg {
					entry, err := backend.Create(ctx, name)
					return createdMsg{entry: entry, err: err}
				}
			}
		case confirming:
			switch key {
			case "y", "Y":
				m.busy, m.err, m.notice = deleteAction, "", ""
				ctx, backend, target := m.ctx, m.backend, m.deleteTarget
				return m, func() tea.Msg { return deletedMsg{err: backend.Delete(ctx, target)} }
			case "n", "N", "esc", "enter":
				m.mode = browsing
			}
			return m, nil
		case helping:
			// Any key dismisses help without performing its action.
			m.mode = browsing
			return m, nil
		default:
			switch key {
			case "up", "k":
				m.cursor = max(0, m.cursor-1)
			case "down", "j":
				m.cursor = min(max(0, len(m.rows)-1), m.cursor+1)
			case "home", "g":
				m.cursor = 0
			case "end", "G":
				m.cursor = max(0, len(m.rows)-1)
			case "pgup":
				m.cursor = max(0, m.cursor-max(1, m.listHeight()))
			case "pgdown":
				m.cursor = min(max(0, len(m.rows)-1), m.cursor+max(1, m.listHeight()))
			case "enter":
				if entry, ok := m.current(); ok {
					return m, m.connect(entry)
				}
			case "n":
				m.mode, m.err, m.notice = creating, "", ""
				m.input.Reset()
				return m, m.input.Focus()
			case "d":
				if entry, ok := m.current(); ok {
					m.mode, m.deleteTarget, m.err = confirming, entry, ""
				}
			case "?":
				m.mode = helping
			}
			return m, nil
		}
	}
	if m.mode == creating && m.busy == noAction {
		// Editing the name clears the previous submit error; the inline hint
		// reflects the current value immediately.
		m.err = ""
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) connect(entry Entry) tea.Cmd {
	m.Selected = &entry
	return m.quit()
}

func (m *Model) quit() tea.Cmd {
	m.quitting = true
	m.Close()
	return tea.Quit
}

func (m *Model) current() (Entry, bool) {
	if m.cursor < 0 || m.cursor >= len(m.rows) {
		return Entry{}, false
	}
	return m.rows[m.cursor].Entry, true
}

func (m *Model) replaceEntries(entries []Entry) {
	selected := m.preselect
	if current, ok := m.current(); ok {
		selected = current.ID
	}
	m.rows = buildTree(entries)
	m.cursor = min(m.cursor, max(0, len(m.rows)-1))
	for i, row := range m.rows {
		if row.ID == selected {
			m.cursor = i
			break
		}
	}
	m.preselect = ""
	if m.mode == confirming && m.busy == noAction {
		for _, row := range m.rows {
			if row.ID == m.deleteTarget.ID && row.UID == m.deleteTarget.UID {
				m.deleteTarget = row.Entry
				return
			}
		}
		m.mode = browsing
		m.notice = "That blip is no longer available."
	}
}
