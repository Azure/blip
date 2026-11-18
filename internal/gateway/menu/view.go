package menu

import (
	"fmt"
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

const logo = " _     _ _       \n| |__ | (_)_ __  \n| '_ \\| | | '_ \\ \n| |_) | | | |_) |\n|_.__/|_|_| .__/ \n          |_|    "

// The menu keeps a single accent color. Status is carried by position and
// emphasis (reverse video, bold), so it still reads without color support.
var (
	logoStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))
	keyStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))
	promptStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))
	frameStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	selectedStyle        = lipgloss.NewStyle().Reverse(true)
	runningStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	selectedRunningStyle = lipgloss.NewStyle().Reverse(true).Foreground(lipgloss.Color("2"))
	errorStyle           = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("1"))
)

// plainLine keeps backend-provided names, notices, and errors on one line and
// prevents their control sequences from changing the SSH client's terminal.
func plainLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, ansi.Strip(s))
}

func displayName(entry Entry) string {
	if entry.Name != "" {
		return plainLine(entry.Name)
	}
	return plainLine(entry.ID)
}

// layout describes the terminal's current frame. The frame is sized to its
// contents and centered, so short lists do not leave a wall of empty rows.
type layout struct {
	plain   bool // too small or narrow for the frame
	width   int  // frame width, or terminal width when plain
	height  int  // frame height, or terminal height when plain
	left    int  // left margin used to center the frame
	top     int  // blank rows above a compact, centered frame
	logo    int  // rows reserved above the frame for the logo
	list    int  // content rows inside the frame
	status  bool // the status line fits
	message bool // one content row is reserved for a notice or error
}

const maxFrameWidth = 72

func (m *Model) frameWidth() int {
	if m.width <= 0 {
		return 0
	}
	return min(maxFrameWidth, m.width)
}

func (m *Model) contentWidth() int {
	if m.width <= 0 {
		return 0
	}
	if m.width < 32 || m.height < 10 {
		return m.width
	}
	return max(0, m.frameWidth()-4)
}

func (m *Model) layout() layout {
	l := layout{width: m.width, height: m.height, status: true}
	if m.width == 0 || m.height == 0 {
		return l
	}
	l.plain = m.width < 32 || m.height < 10
	l.message = m.err != "" || m.notice != ""
	if l.plain {
		// A one-row terminal shows the selected row alone; keys would not fit.
		l.status = l.height > 1
		l.list = l.height
		if l.status {
			l.list--
		}
		if l.message && l.list > 1 {
			l.list--
		} else {
			l.message = false
		}
	} else {
		l.width = m.frameWidth()
		if m.height >= 20 && m.width >= 40 {
			l.logo = 7
		}
		// Size the frame to its contents, then center it. A short list should
		// not leave a wall of empty rows on a tall terminal.
		rows := len(m.rows)
		switch {
		case m.mode != browsing || m.busy != noAction:
			// Size each dialog to its own content instead of a fixed block.
			rows = len(m.dialogLines(max(0, l.width-4))) + 1
		case rows == 0:
			rows = 4
		}
		l.height = rows + 5
		if l.message {
			l.height++
		}
		l.height = min(m.height-l.logo, max(8, l.height))
		l.top = max(0, (m.height-(l.logo+l.height))/2)
		l.left = max(0, (m.width-l.width)/2)
		l.list = max(0, l.height-4)
		if l.message {
			l.list = max(0, l.list-1)
		}
	}
	return l
}

func (m *Model) listHeight() int {
	return m.layout().list
}

// padLine truncates to width and fills the remainder, preserving ANSI styling.
func padLine(s string, width int) string {
	if width <= 0 {
		return ""
	}
	s = ansi.Truncate(s, width, "~")
	return s + strings.Repeat(" ", max(0, width-lipgloss.Width(s)))
}

func blankLine(width int) string {
	return strings.Repeat(" ", max(0, width))
}

func isBlank(line string) bool {
	return strings.TrimSpace(ansi.Strip(line)) == ""
}

func (m *Model) visibleRange() (int, int) {
	height := m.listHeight()
	start := min(m.offset, max(0, len(m.rows)-height))
	if m.cursor < start {
		start = m.cursor
	} else if m.cursor >= start+height {
		start = max(0, m.cursor-height+1)
	}
	return start, min(len(m.rows), start+height)
}

func (m *Model) ensureVisible() {
	m.offset, _ = m.visibleRange()
}

func (m *Model) renderRow(index, width int) string {
	row := m.rows[index]
	selected := index == m.cursor
	marker := "  "
	if selected {
		marker = "▸ "
	}
	badge := ""
	if row.Running {
		badge = "● running"
	} else if row.ForkOnly {
		badge = "base"
	}
	avail := width - lipgloss.Width(marker)
	if width < 20 {
		badge = ""
	}
	prefix := row.prefix
	if limit := avail / 3; lipgloss.Width(prefix) > limit {
		prefix = ansi.TruncateLeft(prefix, lipgloss.Width(prefix)-limit, "")
	}
	nameWidth := max(1, avail-lipgloss.Width(prefix)-lipgloss.Width(badge)-2)
	name := ansi.Truncate(displayName(row.Entry), nameWidth, "~")
	text := ansi.Truncate(marker+prefix+name, max(0, width-lipgloss.Width(badge)), "")
	text += strings.Repeat(" ", max(0, width-lipgloss.Width(text)-lipgloss.Width(badge)))
	if !selected {
		if badge == "" {
			return text
		}
		return text + runningStyle.Render(badge)
	}
	// Style the bar and the badge separately: a reset inside the badge would
	// otherwise end the highlight partway across the row.
	if badge == "" {
		return selectedStyle.Render(text)
	}
	return selectedStyle.Render(text) + selectedRunningStyle.Render(badge)
}

func (m *Model) emptyState(width int) string {
	if !m.loaded && m.loading {
		if width >= len("Loading...") {
			return "Loading..."
		}
		return "loading"
	}
	for _, text := range []string{"No blips yet. Press n to create one.", "No blips. Press n.", "n = new blip", "n new"} {
		if width >= len(text) {
			return text
		}
	}
	return "n new"
}

func (m *Model) listContent(width, rows int) []string {
	out := make([]string, 0, rows)
	if len(m.rows) == 0 {
		empty := m.emptyState(width)
		top := 0
		if rows > 3 {
			top = (rows - 1) / 2
		}
		for range top {
			out = append(out, blankLine(width))
		}
		line := ansi.Truncate(empty, width, "")
		left := max(0, (width-lipgloss.Width(line))/2)
		out = append(out, dimStyle.Render(strings.Repeat(" ", left)+line))
	} else {
		start, end := m.visibleRange()
		for i := start; i < end; i++ {
			out = append(out, m.renderRow(i, width))
		}
	}
	for len(out) < rows {
		out = append(out, blankLine(width))
	}
	if len(out) > rows {
		out = out[:rows]
	}
	return out
}

func (m *Model) createLines(width int) []string {
	name := strings.TrimSpace(m.input.Value())
	hint := dimStyle.Render("Lowercase letters, digits, dashes")
	if name != "" {
		if err := m.backend.ValidateName(name); err != nil {
			hint = errorStyle.Render("! " + plainLine(err.Error()))
		}
	}
	lines := []string{
		"",
		"  " + dimStyle.Render("Name:"),
		"  " + padLine(m.input.View(), width-2),
		"",
		"  " + padLine(hint, width-2),
	}
	if m.forkTarget != nil {
		lines = append([]string{"", "  Fork " + accent(displayName(*m.forkTarget))}, lines...)
	}
	return lines
}

func (m *Model) deleteLines(width int) []string {
	name := displayName(m.deleteTarget)
	lines := []string{"", "  Delete " + accent(`"`+name+`"`) + "?"}
	if m.deleteTarget.Running {
		warning := "Its running session will end."
		if width < lipgloss.Width(warning)+2 {
			warning = "Running session ends."
		}
		lines = append(lines, "", "  "+warning)
	}
	return lines
}

func accent(s string) string {
	return titleStyle.Render(s)
}

func helpLines(width int) []string {
	rows := [][2]string{
		{"↑/↓  j/k", "move"},
		{"enter", "connect"},
		{"n", "new blip"},
		{"f", "fork selected"},
		{"d", "delete"},
		{"?", "help"},
		{"q", "quit"},
	}
	keyWidth := 0
	for _, row := range rows {
		keyWidth = max(keyWidth, lipgloss.Width(row[0]))
	}
	lines := []string{""}
	for _, row := range rows {
		keys := keyStyle.Render(row[0])
		gap := strings.Repeat(" ", keyWidth-lipgloss.Width(row[0])+2)
		lines = append(lines, padLine("  "+keys+gap+dimStyle.Render(row[1]), width))
	}
	return lines
}

func (m *Model) busyLines() []string {
	name := displayName(m.deleteTarget)
	if m.busy == createAction {
		name = strings.TrimSpace(m.input.Value())
	}
	verb := "Creating"
	if m.busy == deleteAction {
		verb = "Deleting"
	}
	return []string{"", "  " + verb + " " + accent(plainLine(name)) + "..."}
}

func (m *Model) dialogLines(width int) []string {
	var lines []string
	switch {
	case m.busy != noAction:
		lines = m.busyLines()
	case m.mode == creating:
		lines = m.createLines(width)
	case m.mode == confirming:
		lines = m.deleteLines(width)
	case m.mode == helping:
		lines = helpLines(width)
	}
	out := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		out = append(out, padLine(line, width))
	}
	return out
}

// content returns exactly rows lines, each exactly width columns wide.
func (m *Model) content(width, rows int) []string {
	if rows <= 0 {
		return nil
	}
	var out []string
	if m.mode == browsing && m.busy == noAction {
		out = m.listContent(width, rows)
	} else {
		out = m.dialogLines(width)
		// Drop the dialog's leading blank row first when space is scarce.
		for len(out) > rows && len(out) > 0 && isBlank(out[0]) {
			out = out[1:]
		}
		for len(out) < rows {
			out = append(out, blankLine(width))
		}
	}
	if len(out) > rows {
		out = out[:rows]
	}
	return out
}

func (m *Model) message(width int) string {
	if m.err != "" {
		return errorStyle.Render(padLine("! "+plainLine(m.err), width))
	}
	if m.notice != "" {
		return dimStyle.Render(padLine(plainLine(m.notice), width))
	}
	return blankLine(width)
}

type hint struct{ key, label string }

func (m *Model) hints() []hint {
	switch {
	case m.busy != noAction:
		return []hint{{"q", "quit"}}
	case m.mode == creating:
		return []hint{{"enter", "create"}, {"esc", "cancel"}}
	case m.mode == confirming:
		return []hint{{"y", "delete"}, {"n", "cancel"}}
	case m.mode == helping:
		return []hint{{"any key", "close"}}
	}
	if entry, ok := m.current(); ok && entry.ForkOnly {
		if !entry.Shared {
			return []hint{{"enter", "fork"}, {"n", "new"}, {"d", "delete"}, {"?", "help"}, {"q", "quit"}}
		}
		return []hint{{"enter", "fork"}, {"n", "new"}, {"?", "help"}, {"q", "quit"}}
	}
	return []hint{{"enter", "connect"}, {"n", "new"}, {"f", "fork"}, {"d", "delete"}, {"?", "help"}, {"q", "quit"}}
}

func renderHints(hints []hint, width int) string {
	// Prefer airy spacing, then compact to one space before hiding hints.
	for _, separator := range []string{"  ", " "} {
		remaining := hints
		for len(remaining) > 0 {
			var b strings.Builder
			for i, h := range remaining {
				if i > 0 {
					b.WriteString(separator)
				}
				if h.key != "" {
					b.WriteString(keyStyle.Render(h.key))
					b.WriteString(" ")
				}
				b.WriteString(dimStyle.Render(h.label))
			}
			s := b.String()
			if lipgloss.Width(s) <= width || len(remaining) == 1 {
				return s
			}
			remaining = remaining[:len(remaining)-1]
		}
	}
	return ""
}

func (m *Model) position() string {
	if m.mode != browsing || m.busy != noAction || len(m.rows) <= m.listHeight() {
		return ""
	}
	return fmt.Sprintf("%d/%d", m.cursor+1, len(m.rows))
}

func (m *Model) statusLine(width int) string {
	position := m.position()
	available := width
	if position != "" {
		available -= lipgloss.Width(position) + 2
	}
	left := renderHints(m.hints(), max(0, available))
	gap := width - lipgloss.Width(left) - lipgloss.Width(position)
	if position == "" || gap < 1 {
		return padLine(left, width)
	}
	return left + strings.Repeat(" ", gap) + dimStyle.Render(position)
}

func (m *Model) title() (string, string) {
	switch {
	case m.busy == createAction:
		return "creating", ""
	case m.busy == deleteAction:
		return "deleting", ""
	case m.mode == creating:
		if m.forkTarget != nil {
			return "fork blip", ""
		}
		return "new blip", ""
	case m.mode == confirming:
		return "delete blip", ""
	case m.mode == helping:
		return "help", ""
	}
	return "blip", plainLine(m.owner)
}

func (m *Model) topBorder(width int) string {
	title, right := m.title()
	titleText := " " + plainLine(title) + " "
	rightText := ""
	if right != "" {
		rightText = " " + right + " "
	}
	inner := width - 2
	fill := inner - 1 - lipgloss.Width(titleText) - lipgloss.Width(rightText) - 1
	if fill < 0 {
		rightText = ""
		fill = inner - 1 - lipgloss.Width(titleText) - 1
	}
	if fill < 0 {
		titleText, fill = " ", max(0, inner-3)
	}
	line := frameStyle.Render("┌─") + titleStyle.Render(titleText) +
		frameStyle.Render(strings.Repeat("─", fill)) + dimStyle.Render(rightText) +
		frameStyle.Render("─┐")
	return ansi.Truncate(line, width, "")
}

func (m *Model) frameLine(content string, width int) string {
	return frameStyle.Render("│") + " " + padLine(content, max(0, width-4)) + " " + frameStyle.Render("│")
}

func (m *Model) viewFrame(l layout) []string {
	width := l.width
	out := []string{padLeft(m.topBorder(width), l.left)}
	for _, line := range m.content(max(0, width-4), l.list) {
		out = append(out, padLeft(m.frameLine(line, width), l.left))
	}
	if l.message {
		out = append(out, padLeft(m.frameLine(m.message(max(0, width-4)), width), l.left))
	}
	separator := frameStyle.Render("├" + strings.Repeat("─", width-2) + "┤")
	out = append(out,
		padLeft(separator, l.left),
		padLeft(m.frameLine(m.statusLine(max(0, width-4)), width), l.left),
		padLeft(frameStyle.Render("└"+strings.Repeat("─", width-2)+"┘"), l.left),
	)
	return out
}

func (m *Model) viewPlain(l layout) []string {
	out := m.content(l.width, l.list)
	if l.message {
		out = append(out, m.message(l.width))
	}
	if l.status {
		out = append(out, m.statusLine(l.width))
	}
	return out
}

func padLeft(s string, n int) string {
	if n <= 0 {
		return s
	}
	return strings.Repeat(" ", n) + s
}

// View implements Bubble Tea v2's view API. All drawing is bounded by the
// current SSH window; the selected row remains visible after updates/resizes.
func (m *Model) View() tea.View {
	view := tea.NewView("")
	view.AltScreen = true
	if m.width <= 0 || m.height <= 0 {
		return view
	}
	l := m.layout()
	lines := make([]string, 0, m.height)
	lines = append(lines, make([]string, l.top)...)
	if l.logo > 0 {
		for _, line := range strings.Split(logo, "\n") {
			left := max(0, (m.width-lipgloss.Width(line))/2)
			lines = append(lines, padLeft(logoStyle.Render(line), left))
		}
		lines = append(lines, "")
	}
	if l.plain {
		lines = append(lines, m.viewPlain(l)...)
	} else {
		lines = append(lines, m.viewFrame(l)...)
	}
	for len(lines) < m.height {
		lines = append(lines, "")
	}
	for i, line := range lines {
		lines[i] = ansi.Truncate(line, m.width, "")
	}
	view.SetContent(strings.Join(lines, "\n"))
	return view
}
