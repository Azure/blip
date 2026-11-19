package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// ambiguousCommandFlag returns the first flag-looking token that pflag parsed
// after the command's own arguments began without an explicit "--". pflag
// parses interspersed flags, so "run echo -n ns" silently applies -n to blip
// instead of passing it to echo. The token is returned only when it is a known
// blip flag; unknown flags already fail parsing with a clear error.
func ambiguousCommandFlag(cmd *cobra.Command, argv []string) (string, bool) {
	i := skipUntilCommand(cmd, argv)
	positionals := 0
	for i < len(argv) {
		arg := argv[i]
		if arg == "--" {
			// Everything after -- belongs to the command.
			return "", false
		}
		isFlag, needsValue := blipFlag(cmd, arg)
		if !isFlag {
			positionals++
			i++
			continue
		}
		if positionals > 0 {
			return arg, true
		}
		i++
		if needsValue {
			i++
		}
	}
	return "", false
}

// rejectAmbiguousCommandFlags refuses a command line where a blip flag follows
// the command without an explicit "--". Without this pflag silently parses the
// token as a blip flag, so the command runs with different arguments than the
// user wrote.
func (a *app) rejectAmbiguousCommandFlags(cmd *cobra.Command, usage string) error {
	if arg, ok := ambiguousCommandFlag(cmd, a.args); ok {
		return fmt.Errorf("flag %q was parsed by blip after the command began; put -- before the command so it is passed through: %s", arg, usage)
	}
	return nil
}

// skipUntilCommand returns the index just after the subcommand name, skipping
// flags and their values before it.
func skipUntilCommand(cmd *cobra.Command, argv []string) int {
	for i := 0; i < len(argv); {
		arg := argv[i]
		if arg == cmd.Name() {
			return i + 1
		}
		if arg == "--" {
			return len(argv)
		}
		isFlag, needsValue := blipFlag(cmd, arg)
		if !isFlag {
			i++
			continue
		}
		i++
		if needsValue {
			i++
		}
	}
	return len(argv)
}

// blipFlag reports whether arg is a flag of this command (including inherited
// persistent flags) and whether it consumes the following argument as a value.
func blipFlag(cmd *cobra.Command, arg string) (bool, bool) {
	switch {
	case strings.HasPrefix(arg, "--") && len(arg) > 2:
		name, _, hasValue := strings.Cut(arg[2:], "=")
		f := cmd.Flags().Lookup(name)
		if f == nil {
			return false, false
		}
		return true, !hasValue && f.NoOptDefVal == ""
	case strings.HasPrefix(arg, "-") && len(arg) > 1:
		rest := arg[1:]
		for len(rest) > 0 {
			f := cmd.Flags().ShorthandLookup(rest[:1])
			if f == nil {
				return false, false
			}
			if f.NoOptDefVal != "" {
				rest = rest[1:]
				// A boolean shorthand takes no separate value, but pflag
				// accepts an attached one ("-t=false"). Treat it as part of
				// this flag instead of looking up "=" as another shorthand.
				if strings.HasPrefix(rest, "=") {
					return true, false
				}
				continue
			}
			return true, len(rest) == 1
		}
		return true, false
	}
	return false, false
}
