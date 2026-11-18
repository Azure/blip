package menu

import (
	"fmt"
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

const (
	logo        = " _     _ _       \n| |__ | (_)_ __  \n| '_ \\| | | '_ \\ \n| |_) | | | |_) |\n|_.__/|_|_| .__/ \n          |_|    "
	description = "Your personal blips:"
)

var (
	logoStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))
	selectedStyle = lipgloss.NewStyle().Reverse(true)
	runningStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	errorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
)

// plainLine keeps backend-provided names, notices, and errors on one line and
// prevents their control sequences from changing the SSH client's terminal.
func plainLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
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

func (m *Model) footer() []string {
	var lines []string
	switch {
	case m.busy == createAction:
		lines = []string{"Creating blip...", "q / Ctrl-C / Ctrl-D quit"}
	case m.busy == deleteAction:
		lines = []string{"Deleting blip...", "q / Ctrl-C / Ctrl-D quit"}
	case m.mode == creating:
		lines = []string{m.input.View(), "Enter create + connect  Esc cancel", "Uses the configured image."}
	case m.mode == confirming:
		name := ansi.Truncate(displayName(m.deleteTarget), max(1, m.width-16), "~")
		lines = []string{"Delete " + name + "? [y/N]", "y delete  Enter / n / Esc cancel"}
	case m.mode == helping:
		lines = []string{
			"Up/Down or j/k move  Enter connect",
			"n new blip  d delete  ? / Esc back",
			"q / Ctrl-C / Ctrl-D quit",
		}
	default:
		keys := "Enter connect  n new  d delete  q quit"
		if m.width < len(keys) {
			keys = "Enter connect  n new  q quit"
		}
		if m.width < len(keys) {
			keys = "Enter  n new  q quit"
		}
		if m.width < len(keys) {
			keys = "q quit"
		}
		lines = []string{keys}
	}
	if m.err != "" {
		lines = append([]string{errorStyle.Render(plainLine(m.err))}, lines...)
	} else if m.notice != "" {
		lines = append([]string{plainLine(m.notice)}, lines...)
	}
	return lines
}

// layout reserves a scrolling list between the logo and the interaction hint.
// On very small terminals the logo yields first, then secondary hints.
func (m *Model) layout() (header, footer []string, listHeight int) {
	if m.height == 0 {
		return nil, nil, 0
	}
	header = []string{logoStyle.Render("[ blip ]")}
	footer = m.footer()
	if m.width >= len(description) && m.height >= 14+len(footer) {
		header = append(strings.Split(logoStyle.Render(logo), "\n"), description, "")
	}
	if len(footer) >= m.height {
		if m.mode == browsing && m.busy == noAction {
			footer = footer[:max(0, m.height-1)]
		} else {
			return nil, footer[:m.height], 0
		}
	}
	if len(header)+len(footer)+1 > m.height {
		header = nil
	}
	return header, footer, max(0, m.height-len(header)-len(footer))
}

func (m *Model) listHeight() int {
	_, _, height := m.layout()
	return height
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

func (m *Model) renderRow(index int) string {
	row := m.rows[index]
	marker := "  "
	if index == m.cursor {
		marker = "> "
	}
	width := max(0, m.width-len(marker))
	suffix := ""
	if row.Running && width >= len(" Running")+2 {
		suffix = " " + runningStyle.Render("Running")
	}
	prefix := row.prefix
	prefixWidth := max(0, min(width/3, width-lipgloss.Width(suffix)-1))
	if len(prefix) > prefixWidth {
		prefix = ansi.TruncateLeft(prefix, len(prefix)-prefixWidth, "")
	}
	nameWidth := max(1, width-len(prefix)-lipgloss.Width(suffix))
	name := ansi.Truncate(displayName(row.Entry), nameWidth, "~")
	line := ansi.Truncate(marker+prefix+name+suffix, m.width, "")
	if index == m.cursor {
		return selectedStyle.Render(line)
	}
	return line
}

// View implements Bubble Tea v2's view API. All drawing is bounded by the
// current SSH window; the selected row remains visible after updates/resizes.
func (m *Model) View() tea.View {
	view := tea.NewView("")
	view.AltScreen = true
	if m.width == 0 || m.height == 0 {
		return view
	}
	header, footer, height := m.layout()
	lines := append([]string{}, header...)
	start, end := m.visibleRange()
	for i := start; i < end; i++ {
		lines = append(lines, m.renderRow(i))
	}
	if len(m.rows) == 0 && height > 0 {
		empty := "No blips yet. Press n to create one."
		if m.width < len(empty) {
			empty = "n: new blip"
		}
		if !m.loaded && m.loading {
			empty = "Loading blips..."
		}
		lines = append(lines, empty)
	}
	for len(lines) < len(header)+height {
		lines = append(lines, "")
	}
	if len(m.rows) > height && len(footer) > 0 && m.mode == browsing {
		position := fmt.Sprintf("  %d/%d", m.cursor+1, len(m.rows))
		last := len(footer) - 1
		if lipgloss.Width(footer[last])+len(position) <= m.width {
			footer[last] += position
		}
	}
	lines = append(lines, footer...)
	for i, line := range lines {
		lines[i] = ansi.Truncate(line, m.width, "")
	}
	view.SetContent(strings.Join(lines, "\n"))
	return view
}
