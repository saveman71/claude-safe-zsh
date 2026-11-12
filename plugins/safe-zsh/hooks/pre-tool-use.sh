#!/bin/sh
# Claude Code's safety check parses commands with a bash grammar that has no ${(flags)...}, so it refuses them as a possible
# dangerous rm before any shell starts, and setopt cannot help (anthropics/claude-code#104925). This hook runs before that
# check and only ever denies, so the model is told what is really wrong. It never approves anything. It also denies the bash
# indirect expansion ${!name}, which zsh stops at with bad substitution; ${!} (the last background pid) is valid in zsh.
# shortcut: single quotes are stripped without parsing, so an apostrophe inside double quotes can hide a flag (the built-in
# check still refuses it), and a quoted heredoc body counts as code; upgrade if real commands hit either.
command=$(sed -nE 's/.*"command"[[:space:]]*:[[:space:]]*"(([^"\\]|\\.)*)".*/\1/p' | sed "s/'[^']*'//g")
case "$command" in
  *'${('*)
    cat <<'EOF'
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"safe-zsh: this command uses a zsh ${(flags)...} expansion. Claude Code's safety check cannot parse it and would refuse the command as a possible dangerous rm, although the command has not run. Rewrite it in POSIX sh: split a variable with printf '%s\\n' \"$PATH\" | tr ':' '\\n', and read lines with while IFS= read -r line; do ...; done < file. Do not wrap it in zsh -c, eval or a script to get past the check. If it is literal text in a heredoc, write the file with the Write tool."}}
EOF
    ;;
  *'${!'[A-Za-z_]*)
    cat <<'EOF'
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"safe-zsh: this command uses the bash indirect expansion ${!name} or ${!array[@]}. The Bash tool's shell is zsh, which stops at it with bad substitution, so the rest of that subshell or loop never runs. zsh's own ${(P)name} is refused by Claude Code's safety check. Read an exported variable with printenv \"$name\", or run the bash code inside bash -c '...'."}}
EOF
    ;;
esac
