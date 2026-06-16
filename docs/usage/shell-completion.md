# Shell Completion

`mas-sentry` ships tab completion for bash, zsh, and fish via Typer. The
version is printed with `mas-sentry --version`.

## Install for the current shell

```bash
mas-sentry --install-completion
```

This detects the active shell, writes the completion script, and updates the
shell startup file. Restart the shell (or source the startup file) to activate.

## Inspect the script first

To review or customise before installing:

```bash
mas-sentry --show-completion
```

Redirect the output to a file under the shell's completion directory if manual
placement is preferred, e.g. for zsh:

```bash
mas-sentry --show-completion > ~/.zsh/completions/_mas-sentry
```

## Notes

- Completion covers subcommands (`abfp`, `mcp`, `agentic`, `report`, `doctor`)
  and their options.
- After upgrading the toolkit, re-run `--install-completion` only if new
  top-level commands were added; option-level completion resolves dynamically.
