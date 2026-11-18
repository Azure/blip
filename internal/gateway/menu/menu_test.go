package menu

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

type fakeBackend struct {
	entries      []Entry
	changes      chan struct{}
	listCalls    int
	createNames  []string
	deleted      []Entry
	created      Entry
	listErr      error
	createErr    error
	deleteErr    error
	contexts     []context.Context
	unsubscribed atomic.Int32
}

func (b *fakeBackend) List(ctx context.Context) ([]Entry, error) {
	b.listCalls++
	b.contexts = append(b.contexts, ctx)
	return slices.Clone(b.entries), b.listErr
}

func (b *fakeBackend) Create(ctx context.Context, name string) (Entry, error) {
	b.contexts = append(b.contexts, ctx)
	b.createNames = append(b.createNames, name)
	return b.created, b.createErr
}

func (b *fakeBackend) Delete(ctx context.Context, entry Entry) error {
	b.contexts = append(b.contexts, ctx)
	b.deleted = append(b.deleted, entry)
	return b.deleteErr
}

func (b *fakeBackend) Subscribe() (<-chan struct{}, func()) {
	return b.changes, func() { b.unsubscribed.Add(1) }
}

func testModel(t *testing.T, entries []Entry, selected string) (*Model, *fakeBackend) {
	t.Helper()
	b := &fakeBackend{entries: entries, changes: make(chan struct{}, 1)}
	m := New(context.Background(), b, selected, 80, 24, "")
	t.Cleanup(m.Close)
	m.Update(m.reload()())
	return m, b
}

func press(m *Model, key string) tea.Cmd {
	msg := tea.KeyPressMsg{}
	switch key {
	case "enter":
		msg.Code = tea.KeyEnter
	case "esc":
		msg.Code = tea.KeyEscape
	case "up":
		msg.Code = tea.KeyUp
	case "down":
		msg.Code = tea.KeyDown
	case "home":
		msg.Code = tea.KeyHome
	case "end":
		msg.Code = tea.KeyEnd
	case "pgup":
		msg.Code = tea.KeyPgUp
	case "pgdown":
		msg.Code = tea.KeyPgDown
	case "ctrl+c", "ctrl+d":
		msg.Code, msg.Mod = rune(key[len(key)-1]), tea.ModCtrl
	default:
		msg.Code, msg.Text = []rune(key)[0], key
	}
	_, cmd := m.Update(msg)
	return cmd
}

func selectedID(m *Model) string {
	entry, _ := m.current()
	return entry.ID
}

func TestTreePreservesForksAndOrdering(t *testing.T) {
	entries := []Entry{
		{ID: "worker.child", Name: "worker", Parent: "owner.dev"},
		{ID: "owner.z", Name: "zebra"},
		{ID: "owner.fork", Name: "Alpha", Parent: "owner.dev"},
		{ID: "owner.dev", Name: "dev"},
		{ID: "owner.grandchild", Name: "deep", Parent: "owner.fork"},
		{ID: "owner.orphan", Name: "orphan", Parent: "deleted.parent"},
	}
	rows := buildTree(entries)
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	want := []string{"owner.dev", "owner.fork", "owner.grandchild", "worker.child", "owner.orphan", "owner.z"}
	if !slices.Equal(ids, want) {
		t.Fatalf("tree order = %v, want %v", ids, want)
	}
	if rows[1].prefix == "" || len(rows[2].prefix) <= len(rows[1].prefix) || rows[4].prefix != "" {
		t.Fatalf("hierarchy did not preserve children and orphan roots: %#v", rows)
	}
	slices.Reverse(entries)
	if !reflect.DeepEqual(rows, buildTree(entries)) {
		t.Fatal("tree depends on backend list ordering")
	}
}

func TestTreeCyclesAreDeterministicAndKeepEveryEntry(t *testing.T) {
	entries := []Entry{
		{ID: "b", Name: "B", Parent: "c"},
		{ID: "a", Name: "A", Parent: "b"},
		{ID: "c", Name: "C", Parent: "a"},
		{ID: "child", Name: "0-child", Parent: "c"},
		{ID: "self", Name: "Self", Parent: "self"},
	}
	rows := buildTree(entries)
	seen := map[string]bool{}
	for _, row := range rows {
		if seen[row.ID] {
			t.Fatalf("resource %s appeared twice", row.ID)
		}
		seen[row.ID] = true
	}
	if len(seen) != len(entries) {
		t.Fatalf("cycle hid resources: %v", seen)
	}
	if rows[0].ID != "a" || rows[0].prefix != "" {
		t.Fatal("cycle should break at its alphabetically first member")
	}
	slices.Reverse(entries)
	if !reflect.DeepEqual(rows, buildTree(entries)) {
		t.Fatal("cycle resolution changed with list ordering")
	}
}

func TestSelectionSurvivesReorderAndParentDeletion(t *testing.T) {
	entries := []Entry{
		{ID: "owner.root", Name: "root"},
		{ID: "worker.fork", Name: "fork", Parent: "owner.root"},
		{ID: "owner.other", Name: "other"},
	}
	m, _ := testModel(t, entries, "worker.fork")
	if selectedID(m) != "worker.fork" {
		t.Fatal("initial full resource ID was not preselected")
	}
	entries = append(entries[1:], Entry{ID: "owner.aaa", Name: "aaa"})
	entries[0].Running = true
	m.Update(listMsg{entries: entries})
	if selectedID(m) != "worker.fork" || !m.rows[m.cursor].Running || m.rows[m.cursor].prefix != "" {
		t.Fatal("selection or entry data lost after reparenting to a root")
	}
	press(m, "down")
	id := selectedID(m)
	slices.Reverse(entries)
	m.Update(listMsg{entries: entries})
	if selectedID(m) != id {
		t.Fatal("live refresh overwrote user's selection with initial preselection")
	}
	m.Update(listMsg{entries: []Entry{{ID: "last", Name: "last"}}})
	if selectedID(m) != "last" {
		t.Fatal("deleted selection did not fall back to a valid row")
	}
	m.Update(listMsg{})
	if _, ok := m.current(); ok || m.cursor != 0 {
		t.Fatal("empty list retained an invalid selection")
	}
}

func TestNavigationAndConnect(t *testing.T) {
	entries := []Entry{{ID: "a", Name: "a"}, {ID: "b", Name: "b"}, {ID: "c", Name: "c"}}
	m, b := testModel(t, entries, "missing")
	for _, key := range []string{"up", "k"} {
		press(m, key)
		if selectedID(m) != "a" {
			t.Fatal("navigation moved above first row")
		}
	}
	press(m, "j")
	press(m, "down")
	press(m, "down")
	if selectedID(m) != "c" {
		t.Fatal("downward navigation did not clamp at last row")
	}
	press(m, "k")
	cmd := press(m, "enter")
	if cmd == nil || m.Selected == nil || m.Selected.ID != "b" {
		t.Fatal("Enter did not select the highlighted resource")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("connect did not quit the Bubble Tea program")
	}
	if b.unsubscribed.Load() != 1 || m.ctx.Err() == nil {
		t.Fatal("connect did not release background work")
	}
}

func TestQuitKeys(t *testing.T) {
	for _, key := range []string{"q", "ctrl+c", "ctrl+d"} {
		t.Run(key, func(t *testing.T) {
			m, _ := testModel(t, []Entry{{ID: "a", Name: "a"}}, "")
			cmd := press(m, key)
			if cmd == nil || m.Selected != nil {
				t.Fatal("quit selected a resource or failed to return a command")
			}
			if _, ok := cmd().(tea.QuitMsg); !ok {
				t.Fatal("quit key did not quit")
			}
			m.Update(createdMsg{entry: Entry{ID: "late"}})
			if m.Selected != nil {
				t.Fatal("late create result overrode explicit quit")
			}
		})
	}
}

func TestCreateIsAsyncAndConnectsReturnedEntry(t *testing.T) {
	m, b := testModel(t, nil, "")
	b.created = Entry{ID: "owner.quick", UID: "new-uid", Name: "quick"}
	press(m, "n")
	if m.mode != creating || !m.input.Focused() {
		t.Fatal("n did not focus the create prompt")
	}
	if cmd := press(m, "enter"); cmd != nil || len(b.createNames) != 0 {
		t.Fatal("empty name created a resource")
	}
	for _, r := range "quick" {
		press(m, string(r))
	}
	cmd := press(m, "enter")
	if cmd == nil || len(b.createNames) != 0 || m.Selected != nil {
		t.Fatal("create did not defer backend work until the command runs")
	}
	if press(m, "enter") != nil {
		t.Fatal("duplicate submit started another create")
	}
	_, quit := m.Update(cmd())
	if !slices.Equal(b.createNames, []string{"quick"}) || m.Selected == nil || *m.Selected != b.created {
		t.Fatalf("create/connect mismatch: names=%v, selected=%v", b.createNames, m.Selected)
	}
	if _, ok := quit().(tea.QuitMsg); !ok {
		t.Fatal("successful create did not connect")
	}
}

func TestCreateCancellationAndFailure(t *testing.T) {
	m, b := testModel(t, nil, "")
	press(m, "n")
	press(m, "esc")
	if m.mode != browsing || len(b.createNames) != 0 {
		t.Fatal("escape failed to cancel creation")
	}
	press(m, "n")
	m.input.SetValue("dev")
	b.createErr = errors.New("name already exists")
	cmd := press(m, "enter")
	m.Update(cmd())
	if m.Selected != nil || m.mode != creating || !m.input.Focused() || m.input.Value() != "dev" {
		t.Fatal("failed creation did not retain an editable prompt")
	}
	if !strings.Contains(ansi.Strip(m.View().Content), b.createErr.Error()) {
		t.Fatal("create error was not shown")
	}
	press(m, "ctrl+d")
	if !m.quitting || m.Selected != nil {
		t.Fatal("Ctrl-D failed to quit the create prompt")
	}
}

func TestDeleteRequiresConfirmationAndKeepsTargetIdentity(t *testing.T) {
	entries := []Entry{{ID: "a", UID: "original-a", Name: "a"}, {ID: "b", UID: "original-b", Name: "b"}}
	m, b := testModel(t, entries, "b")
	press(m, "d")
	press(m, "enter")
	if len(b.deleted) != 0 || m.mode != browsing {
		t.Fatal("Enter should accept the default no answer")
	}
	press(m, "d")
	m.Update(listMsg{entries: append(entries, Entry{ID: "aa", Name: "aa"})})
	press(m, "up")
	cmd := press(m, "y")
	if cmd == nil || len(b.deleted) != 0 {
		t.Fatal("delete was not asynchronous")
	}
	if press(m, "y") != nil {
		t.Fatal("duplicate confirmation started another delete")
	}
	msg := cmd()
	if len(b.deleted) != 1 || b.deleted[0] != entries[1] {
		t.Fatalf("deleted wrong resource identity: %v", b.deleted)
	}
	b.entries = entries[:1]
	_, reload := m.Update(msg)
	m.Update(reload())
	if m.mode != browsing || selectedID(m) != "a" || m.Selected != nil {
		t.Fatal("delete did not return to a valid menu selection")
	}
}

func TestDeleteConfirmationInvalidatedByReplacement(t *testing.T) {
	m, b := testModel(t, []Entry{{ID: "a", UID: "old", Name: "a"}}, "")
	press(m, "d")
	m.Update(listMsg{entries: []Entry{{ID: "a", UID: "new", Name: "a"}}})
	if cmd := press(m, "y"); cmd != nil || m.mode != browsing || len(b.deleted) != 0 {
		t.Fatal("confirmation survived replacement with a different UID")
	}
}

func TestNotificationsCoalesceAndRearm(t *testing.T) {
	b := &fakeBackend{entries: []Entry{{ID: "a", Name: "a"}}, changes: make(chan struct{}, 1)}
	m := New(context.Background(), b, "", 80, 24, "")
	t.Cleanup(m.Close)
	initial := m.Init()().(tea.BatchMsg)
	if len(initial) != 2 || b.listCalls != 0 {
		t.Fatal("Init should asynchronously load and wait for a notification")
	}
	b.changes <- struct{}{}
	_, nextWait := m.Update(initial[1]())
	if !m.dirty || b.listCalls != 0 || nextWait == nil {
		t.Fatal("notification did not mark the in-flight list dirty and rearm")
	}
	b.changes <- struct{}{}
	m.Update(nextWait())
	_, refresh := m.Update(initial[0]())
	if refresh == nil || m.dirty || b.listCalls != 1 {
		t.Fatal("coalesced changes did not schedule exactly one fresh list")
	}
	b.entries = []Entry{{ID: "b", Name: "b"}}
	m.Update(refresh())
	if b.listCalls != 2 || selectedID(m) != "b" {
		t.Fatal("refresh did not load the latest state")
	}
	for _, ctx := range b.contexts {
		if ctx != m.ctx {
			t.Fatal("backend operation did not receive the model context")
		}
	}
}

func TestCloseCancelsWaitAndUnsubscribesOnce(t *testing.T) {
	m, b := testModel(t, nil, "")
	result := make(chan tea.Msg, 1)
	wait := m.waitForChange()
	go func() { result <- wait() }()
	m.Close()
	m.Close()
	select {
	case msg := <-result:
		if _, ok := msg.(tea.QuitMsg); !ok {
			t.Fatalf("canceled wait returned %T", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("subscription waiter leaked after Close")
	}
	if b.unsubscribed.Load() != 1 {
		t.Fatal("subscription was not released exactly once")
	}
}

func TestClosedSubscriptionDoesNotSpin(t *testing.T) {
	m, b := testModel(t, nil, "")
	close(b.changes)
	_, wait := m.Update(m.waitForChange()())
	if m.changes != nil || b.listCalls != 1 || wait == nil {
		t.Fatal("closed subscription triggered a reload or lost context waiter")
	}
	m.Close()
	if _, ok := wait().(tea.QuitMsg); !ok {
		t.Fatal("closed subscription context waiter did not terminate")
	}
}

func TestResizeAndScrollingKeepSelectionVisible(t *testing.T) {
	entries := make([]Entry, 60)
	for i := range entries {
		entries[i] = Entry{ID: fmt.Sprintf("id-%02d", i), Name: fmt.Sprintf("blip-%02d", i), Running: true}
		if i > 0 {
			entries[i].Parent = entries[i-1].ID
		}
	}
	m, _ := testModel(t, entries, entries[40].ID)
	for _, size := range [][2]int{{80, 24}, {22, 8}, {12, 4}, {1, 1}, {120, 40}, {0, 0}} {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		content := m.View().Content
		if size[0] == 0 || size[1] == 0 {
			if content != "" {
				t.Fatal("zero-size terminal should render no content")
			}
			continue
		}
		if lipgloss.Height(content) > size[1] {
			t.Fatalf("view height exceeds %v", size)
		}
		for _, line := range strings.Split(content, "\n") {
			if lipgloss.Width(line) > size[0] {
				t.Fatalf("view width exceeds %v: %q", size, line)
			}
		}
		start, end := m.visibleRange()
		if m.cursor < start || m.cursor >= end || selectedID(m) != entries[40].ID {
			t.Fatalf("selection not visible/preserved at size %v: range %d:%d", size, start, end)
		}
		if !strings.Contains(ansi.Strip(content), ">") {
			t.Fatalf("selection marker missing at size %v", size)
		}
		if size[0] >= 12 && !strings.Contains(ansi.Strip(content), "Running") {
			t.Fatalf("deeply nested Running indicator hidden at size %v", size)
		}
	}
	m.Update(tea.WindowSizeMsg{Width: 40, Height: 10})
	press(m, "end")
	if selectedID(m) != entries[len(entries)-1].ID {
		t.Fatal("End did not reach the last resource")
	}
	press(m, "pgup")
	if m.cursor == len(entries)-1 {
		t.Fatal("page up did not move selection")
	}
	press(m, "home")
	if m.offset != 0 || m.cursor != 0 {
		t.Fatal("Home did not reset scrolling")
	}
}

func TestViewOnlyLabelsRunningStatesAndHasASCIIArt(t *testing.T) {
	m, _ := testModel(t, []Entry{{ID: "a", Name: "alpha", Running: true}, {ID: "b", Name: "beta"}}, "")
	view := ansi.Strip(m.View().Content)
	if !strings.Contains(view, "alpha Running") || !strings.Contains(view, "beta") || strings.Count(view, "Running") != 1 {
		t.Fatalf("unexpected running labels: %s", view)
	}
	for _, status := range []string{"Stopped", "Pending", "Ready", "Idle", "Sealed", "Failed", "Unknown"} {
		if strings.Contains(view, status) {
			t.Fatalf("unrequested state status %q", status)
		}
	}
	for _, r := range logo {
		if r > 127 {
			t.Fatal("logo is not actual ASCII art")
		}
	}
	logoLines := strings.Split(logo, "\n")
	if len(logoLines) != 6 {
		t.Fatalf("logo has %d rows, want 6", len(logoLines))
	}
	for _, line := range logoLines {
		if len(line) != len(logoLines[0]) {
			t.Fatalf("logo rows are ragged: %q", logo)
		}
	}
	if !strings.Contains(view, logo) {
		t.Fatal("normal-size view did not display the logo")
	}
	if !strings.Contains(view, description) {
		t.Fatal("normal-size view did not describe the list")
	}
	if strings.Contains(view, "? help") {
		t.Fatal("footer still advertises help")
	}
	press(m, "?")
	if !strings.Contains(ansi.Strip(m.View().Content), "j/k") || m.mode != helping {
		t.Fatal("help did not describe navigation")
	}
	press(m, "esc")
	if m.mode != browsing {
		t.Fatal("Escape did not dismiss help")
	}
}

func TestEmptyStateAndBackendErrors(t *testing.T) {
	m, b := testModel(t, nil, "")
	if !strings.Contains(ansi.Strip(m.View().Content), "Press n to create") {
		t.Fatal("empty state did not explain how to create a blip")
	}
	if press(m, "enter") != nil || press(m, "d") != nil || m.Selected != nil {
		t.Fatal("empty list allowed an entry action")
	}
	b.listErr = errors.New("temporary disconnection")
	m.Update(m.reload()())
	if !strings.Contains(ansi.Strip(m.View().Content), b.listErr.Error()) {
		t.Fatal("list error was not displayed")
	}
	b.listErr = nil
	b.entries = []Entry{{ID: "a", Name: "a"}}
	m.Update(m.reload()())
	if m.err != "" || selectedID(m) != "a" {
		t.Fatal("successful refresh did not recover from list error")
	}
	press(m, "d")
	b.deleteErr = errors.New("resource changed")
	m.Update(press(m, "y")())
	if !strings.Contains(ansi.Strip(m.View().Content), b.deleteErr.Error()) || m.Selected != nil {
		t.Fatal("delete error did not return to a usable menu")
	}
}

func TestExternalTextCannotEscapeViewBounds(t *testing.T) {
	m, _ := testModel(t, []Entry{{ID: "a", Name: "wide界\n\x1b[2Jname"}}, "")
	m.notice = "hello\r\n\x1b]0;changed-title\a world"
	m.Update(tea.WindowSizeMsg{Width: 15, Height: 5})
	content := m.View().Content
	if strings.Contains(content, "\x1b[2J") || strings.Contains(content, "\x1b]0;") || lipgloss.Height(content) > 5 {
		t.Fatal("backend text escaped its one-line display")
	}
	for _, line := range strings.Split(content, "\n") {
		if lipgloss.Width(line) > 15 {
			t.Fatal("wide display text escaped terminal bounds")
		}
	}
}
