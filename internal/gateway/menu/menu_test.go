package menu

import (
	"context"
	"errors"
	"fmt"
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
	validateErr  error
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

func (b *fakeBackend) ValidateName(name string) error {
	if b.validateErr != nil {
		return b.validateErr
	}
	return nil
}

func (b *fakeBackend) Subscribe() (<-chan struct{}, func()) {
	return b.changes, func() { b.unsubscribed.Add(1) }
}

func testModel(t *testing.T, entries []Entry, selected string) (*Model, *fakeBackend) {
	t.Helper()
	b := &fakeBackend{entries: entries, changes: make(chan struct{}, 1)}
	m := New(context.Background(), b, selected, 80, 24, "", "alice")
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

func entryIDs(entries []Entry) []string {
	ids := make([]string, len(entries))
	for i, entry := range entries {
		ids[i] = entry.ID
	}
	return ids
}

func TestSortEntriesOrdersByDisplayNameThenID(t *testing.T) {
	entries := []Entry{
		{ID: "owner.zeta", Name: "Zeta"},
		{ID: "owner.beta", Name: "beta"},
		{ID: "owner.alpha.2", Name: "alpha"},
		{ID: "owner.alpha.1", Name: "Alpha"},
		{ID: "", Name: "no-id"},
	}
	want := []string{"owner.alpha.1", "owner.alpha.2", "owner.beta", "owner.zeta"}
	if got := entryIDs(sortEntries(entries)); !slices.Equal(got, want) {
		t.Fatalf("sorted order = %v, want %v", got, want)
	}
	if len(entries) != 5 || entries[0].ID != "owner.zeta" {
		t.Fatal("sortEntries mutated its input")
	}
	slices.Reverse(entries)
	if got := entryIDs(sortEntries(entries)); !slices.Equal(got, want) {
		t.Fatalf("order depends on backend list order: %v", got)
	}
	dupes := []Entry{
		{ID: "b", Name: "same"},
		{ID: "a", Name: "Same"},
		{ID: "c", Name: "same"},
	}
	slices.Reverse(dupes)
	if got := entryIDs(sortEntries(dupes)); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("case-insensitive name ties are not broken by resource ID: %v", got)
	}
}

func TestSelectionSurvivesReorder(t *testing.T) {
	entries := []Entry{
		{ID: "owner.root", Name: "root"},
		{ID: "worker.other", Name: "other"},
		{ID: "owner.zzz", Name: "zed"},
	}
	m, _ := testModel(t, entries, "worker.other")
	if selectedID(m) != "worker.other" {
		t.Fatal("initial full resource ID was not preselected")
	}
	entries = []Entry{
		{ID: "owner.root", Name: "root"},
		{ID: "worker.other", Name: "other", Running: true},
		{ID: "owner.aaa", Name: "aaa"},
	}
	m.Update(listMsg{entries: entries})
	current, ok := m.current()
	if !ok || current.ID != "worker.other" || current.Name != "other" || !current.Running {
		t.Fatalf("selection or entry data lost after reorder: %#v", current)
	}
	press(m, "down")
	id := selectedID(m)
	if id != "owner.root" {
		t.Fatalf("selection did not follow sorted order: %s", id)
	}
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

func TestFDoesNothing(t *testing.T) {
	entries := []Entry{
		{ID: "a", Name: "alpha"},
		{ID: "b", Name: "beta"},
	}
	m, b := testModel(t, entries, "a")
	if cmd := press(m, "f"); cmd != nil {
		t.Fatal("f returned a command")
	}
	if m.mode != browsing || m.Selected != nil || m.busy != noAction || m.quitting {
		t.Fatalf("f changed the menu state: mode=%v selected=%v busy=%v", m.mode, m.Selected, m.busy)
	}
	if selectedID(m) != "a" {
		t.Fatal("f changed the selected row")
	}
	if m.input.Focused() || m.input.Value() != "" {
		t.Fatal("f focused the create prompt")
	}
	if len(b.createNames) != 0 {
		t.Fatal("f created a blip")
	}
	view := ansi.Strip(m.View().Content)
	if strings.Contains(strings.ToLower(view), "fork") {
		t.Fatalf("browse view advertises a removed fork action:\n%s", view)
	}
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	press(m, "?")
	if help := ansi.Strip(m.View().Content); strings.Contains(strings.ToLower(help), "fork") {
		t.Fatalf("help still lists a fork action:\n%s", help)
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
	m := New(context.Background(), b, "", 80, 24, "", "alice")
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
		if !strings.Contains(ansi.Strip(content), "▸") {
			t.Fatalf("selection marker missing at size %v", size)
		}
		if size[0] >= 20 && !strings.Contains(ansi.Strip(content), "running") {
			t.Fatalf("running indicator hidden at size %v", size)
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
	if !strings.Contains(view, "alpha") || !strings.Contains(view, "● running") || strings.Count(view, "running") != 1 {
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
	if !strings.Contains(view, logoLines[0]) || !strings.Contains(view, logoLines[5]) {
		t.Fatal("normal-size view did not display the logo")
	}
	for _, frame := range []string{"┌", "┐", "└", "┘", "├", "alice"} {
		if !strings.Contains(view, frame) {
			t.Fatalf("normal-size view is missing frame or owner %q", frame)
		}
	}
	if !strings.Contains(view, "? help") {
		t.Fatal("status line does not advertise help")
	}
	press(m, "?")
	if !strings.Contains(ansi.Strip(m.View().Content), "j/k") || m.mode != helping {
		t.Fatal("help did not describe navigation")
	}
	press(m, "x")
	if m.mode != browsing {
		t.Fatal("any key should dismiss help without acting")
	}
}

func TestCreateDialogValidatesBeforeCreating(t *testing.T) {
	m, b := testModel(t, nil, "")
	press(m, "n")
	for _, r := range "Dev" {
		press(m, string(r))
	}
	b.validateErr = errors.New("use lowercase letters, digits and '-'")
	view := ansi.Strip(m.View().Content)
	if !strings.Contains(view, b.validateErr.Error()) || !strings.Contains(view, "new blip") {
		t.Fatalf("create dialog did not show inline validation:\n%s", view)
	}
	if cmd := press(m, "enter"); cmd != nil || len(b.createNames) != 0 {
		t.Fatal("invalid name reached the backend")
	}
	if m.mode != creating || !m.input.Focused() {
		t.Fatal("invalid name closed the create dialog")
	}
	b.validateErr = nil
	view = ansi.Strip(m.View().Content)
	if !strings.Contains(view, "Lowercase letters") {
		t.Fatalf("create dialog lost its name guidance:\n%s", view)
	}
	if strings.Contains(strings.ToLower(view), "fork") {
		t.Fatalf("create dialog still offers a fork line:\n%s", view)
	}
}

func TestDeleteDialogExplainsRunningSessions(t *testing.T) {
	m, _ := testModel(t, []Entry{{ID: "a", Name: "dev", Running: true}}, "a")
	press(m, "d")
	view := ansi.Strip(m.View().Content)
	if !strings.Contains(view, `Delete "dev"?`) || !strings.Contains(view, "running session will end") {
		t.Fatalf("delete dialog did not warn about the running session:\n%s", view)
	}
	if !strings.Contains(view, "y delete") || !strings.Contains(view, "n cancel") {
		t.Fatalf("delete dialog did not show its keys:\n%s", view)
	}

	m, _ = testModel(t, []Entry{{ID: "b", Name: "idle"}}, "b")
	press(m, "d")
	if view := ansi.Strip(m.View().Content); strings.Contains(view, "running session") {
		t.Fatalf("stopped blip got a running warning:\n%s", view)
	}
}

func TestNarrowTerminalDropsTheFrame(t *testing.T) {
	m, _ := testModel(t, []Entry{{ID: "a", Name: "alpha"}, {ID: "b", Name: "beta"}}, "")
	m.Update(tea.WindowSizeMsg{Width: 24, Height: 8})
	view := ansi.Strip(m.View().Content)
	if strings.ContainsAny(view, "┌┐└┘│├─") {
		t.Fatalf("narrow view kept frame drawing:\n%s", view)
	}
	if !strings.Contains(view, "alpha") || !strings.Contains(view, "enter connect") {
		t.Fatalf("narrow view lost its list or keys:\n%s", view)
	}
}

func checkViewBounds(t *testing.T, m *Model, width, height int) {
	t.Helper()
	content := m.View().Content
	if lipgloss.Height(content) > height {
		t.Fatalf("view height exceeds %dx%d:\n%s", width, height, ansi.Strip(content))
	}
	for _, line := range strings.Split(content, "\n") {
		if lipgloss.Width(line) > width {
			t.Fatalf("view width exceeds %dx%d: %q", width, height, ansi.Strip(line))
		}
	}
}

func TestDialogsKeepScrollAndStayInBounds(t *testing.T) {
	entries := make([]Entry, 60)
	for i := range entries {
		entries[i] = Entry{ID: fmt.Sprintf("id-%02d", i), Name: fmt.Sprintf("blip-%02d", i), Running: i%3 == 0}
	}
	m, _ := testModel(t, entries, "")
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	press(m, "end")
	last, offset := selectedID(m), m.offset
	for _, tc := range []struct{ open, close string }{{"n", "esc"}, {"d", "esc"}, {"?", "x"}} {
		press(m, tc.open)
		checkViewBounds(t, m, 80, 24)
		press(m, tc.close)
		if m.mode != browsing {
			t.Fatalf("%q did not close its dialog", tc.open)
		}
		if m.offset != offset || selectedID(m) != last {
			t.Fatalf("dialog %q changed the list window: offset %d -> %d", tc.open, offset, m.offset)
		}
	}
	for _, size := range [][2]int{{40, 10}, {32, 10}, {24, 8}, {12, 4}, {1, 1}, {120, 40}} {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		for _, tc := range []struct{ open, close string }{{"n", "esc"}, {"d", "esc"}, {"?", "x"}} {
			press(m, tc.open)
			checkViewBounds(t, m, size[0], size[1])
			press(m, tc.close)
		}
	}
}

func TestBusyDialogsStayInBounds(t *testing.T) {
	entries := []Entry{{ID: "a", Name: "alpha"}}
	creating, _ := testModel(t, entries, "")
	press(creating, "n")
	creating.input.SetValue("busy")
	press(creating, "enter")
	checkViewBounds(t, creating, 80, 24)

	deleting, _ := testModel(t, entries, "")
	press(deleting, "d")
	press(deleting, "y")
	checkViewBounds(t, deleting, 80, 24)
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
