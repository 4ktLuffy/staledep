"""Per-call effect typing for shell commands.

Every other tool in this project is typed by NAME: `send_money` always writes the
account, `Read` always reads a file. `Bash` breaks that assumption -- its effect
lives in the argument, not the signature. `Bash(ls)` observes; `Bash(rm -rf)`
destroys. Typing the tool rather than the call is what made 78.3% of windows in
real Claude Code sessions unclassifiable, with `Bash -> Bash` alone accounting
for 65% of them.

Two consequences of getting this right, and the first matters more:

  A read-only shell call is NOT A SINK. Windows ending in `Bash(git status)`
  should never have been created -- there is nothing to move. Removing them
  improves precision, not merely coverage.

  A writing shell call CAN be bound. `rm FILE`, `mv A B` and `> FILE` resolve a
  path at execution: if the tree moved, the effect lands elsewhere. That is
  dereference, the same shape as `delete_file(file_id)`.

Classification is conservative. An unrecognised command stays HIGH/unknown --
guessing that an unfamiliar command is harmless is the one error that would make
the instrument dangerous rather than merely incomplete.
"""

from __future__ import annotations

import os
import re

from .binding import Bind
from .effects import Effect, Risk

_r = frozenset

#: Commands that observe without mutating. A window ending here is not a window.
READ_ONLY = {
    "ls", "cat", "head", "tail", "wc", "grep", "rg", "egrep", "fgrep", "find",
    "which", "type", "file", "stat", "du", "df", "pwd", "whoami", "date", "env",
    "printenv", "uname", "hostname", "ps", "top", "id", "groups", "history",
    "diff", "cmp", "md5", "shasum", "sha256sum", "sort", "uniq", "cut", "awk",
    "sed",           # only without -i; the -i case is caught below
    "jq", "column", "tree", "less", "more", "man", "help", "basename", "dirname",
    "realpath", "readlink", "seq", "printf",
}

#: Subcommands that make an otherwise-mutating tool read-only.
READ_ONLY_SUB = {
    "git": {"log", "status", "diff", "show", "blame", "branch", "remote",
            "ls-files", "rev-parse", "describe", "config", "bisect", "shortlog",
            "count-objects", "cat-file", "tag", "reflog", "stash"},
    "npm": {"ls", "list", "view", "outdated", "config"},
    "pip": {"list", "show", "freeze"},
    "docker": {"ps", "images", "logs", "inspect"},
    "kubectl": {"get", "describe", "logs"},
    "brew": {"list", "info", "search", "outdated"},
    "cargo": {"tree", "search"},
    "go": {"list", "version", "env"},
    "ollama": {"list", "ps", "show"},
}

#: Navigation and shell bookkeeping. These have no file effect of their own and
#: must be SKIPPED rather than classified: `cd x && python y` is a python call,
#: not an unknown one. `cd` alone accounted for 474 of 914 unclassified shell
#: calls in real sessions -- the single largest cause, and entirely spurious.
NEUTRAL = {
    "cd", "pushd", "popd", "export", "set", "unset", "alias", "unalias",
    "source", ".", "true", "false", ":", "eval_off", "umask", "ulimit",
    "shopt", "setopt", "local", "declare", "typeset", "read",
}

#: Shell keywords that open a compound statement. The work is in the body, which
#: `_first_words` already splits out, so the keyword itself carries no effect.
KEYWORDS = {
    "for", "while", "until", "do", "done", "if", "then", "elif", "else", "fi",
    "case", "esac", "function", "select", "in", "{", "}", "(", ")",
}

#: Network fetches. Read-only unless they write the response to a path.
FETCH = {"curl", "wget", "http", "https"}
_FETCH_WRITES = re.compile(r"\s-[oO]\b|--output\b|--remote-name\b")

#: Commands whose effect resolves a path at execution time.
DEREFERENCING = {
    "rm", "rmdir", "mv", "cp", "ln", "truncate", "shred", "chmod", "chown",
    "touch", "mkdir", "install", "unlink", "dd",
}

DEREFERENCING_SUB = {
    "git": {"checkout", "reset", "clean", "restore", "revert", "rebase",
            "merge", "pull", "apply", "rm", "mv"},
}

#: Redirections write a path resolved at execution.
_REDIRECT = re.compile(r"(?<![0-9<>])>{1,2}\s*[^\s|&;]+")
_INPLACE_SED = re.compile(r"\bsed\b[^|;]*\s-i\b")
_PIPE_TO_SHELL = re.compile(r"\|\s*(ba|z|fi)?sh\b")


def _first_words(command: str) -> list[tuple[str, str | None]]:
    """(binary, subcommand) for each segment of a compound command.

    A shell line may chain several commands; the effect of the LINE is the
    strongest effect among them, so each segment is classified.
    """
    out: list[tuple[str, str | None]] = []
    for seg in re.split(r"&&|\|\||;|\|", command):
        toks = seg.strip().split()
        # skip leading environment assignments and common prefixes
        while toks and ("=" in toks[0].split()[0] and not toks[0].startswith("-")):
            toks = toks[1:]
        while toks and toks[0] in {"sudo", "time", "nohup", "exec", "command", "nice"}:
            toks = toks[1:]
        if not toks:
            continue
        binary = os.path.basename(toks[0]) if "/" in toks[0] else toks[0]
        sub = None
        for t in toks[1:]:
            if not t.startswith("-"):
                sub = t
                break
        out.append((binary, sub))
    return out


def classify_command(command: str) -> tuple[Effect, Bind]:
    """Return the effect and binding of one shell invocation.

    Unrecognised commands stay HIGH/unknown. Under-calling a destructive command
    is the only error here that turns an incomplete instrument into a misleading
    one, so the default is pessimistic.
    """
    if not command or not command.strip():
        return Effect(Risk.HIGH, reads=_r({"shell"}), writes=_r({"shell"})), Bind.UNKNOWN

    cmd = command.strip()

    # anything that writes a path, wherever it appears in the line
    if _REDIRECT.search(cmd) or _INPLACE_SED.search(cmd) or _PIPE_TO_SHELL.search(cmd):
        return (Effect(Risk.HIGH, reads=_r({"workspace.files", "shell"}),
                       writes=_r({"workspace.files", "shell"})), Bind.DEREFERENCE)

    segments = _first_words(cmd)
    if not segments:
        return Effect(Risk.HIGH, reads=_r({"shell"}), writes=_r({"shell"})), Bind.UNKNOWN

    worst = Risk.READ
    bind = Bind.SNAPSHOT
    for binary, sub in segments:
        if binary in NEUTRAL or binary in KEYWORDS:
            continue                           # navigation/bookkeeping, no effect
        if binary in FETCH:
            if _FETCH_WRITES.search(cmd):
                return (Effect(Risk.HIGH, reads=_r({"workspace.files", "web"}),
                               writes=_r({"workspace.files"})), Bind.DEREFERENCE)
            continue                           # fetch to stdout is a read
        if binary == "echo":
            continue                           # redirect already handled above
        if binary in DEREFERENCING or (binary in DEREFERENCING_SUB
                                       and sub in DEREFERENCING_SUB[binary]):
            return (Effect(Risk.HIGH, reads=_r({"workspace.files", "shell"}),
                           writes=_r({"workspace.files", "shell"})), Bind.DEREFERENCE)
        if binary in READ_ONLY_SUB:
            if sub in READ_ONLY_SUB[binary]:
                continue                       # read-only subcommand
            return (Effect(Risk.HIGH, reads=_r({"workspace.files", "shell"}),
                           writes=_r({"workspace.files", "shell"})), Bind.UNKNOWN)
        if binary in READ_ONLY:
            continue
        # unrecognised: stay pessimistic
        worst, bind = Risk.HIGH, Bind.UNKNOWN

    if worst is Risk.READ:
        # observes only -- NOT a sink, so no window may end here
        return Effect(Risk.READ, reads=_r({"workspace.files", "shell"})), Bind.SNAPSHOT
    return (Effect(Risk.HIGH, reads=_r({"workspace.files", "shell"}),
                   writes=_r({"workspace.files", "shell"})), bind)


def effect_for_step(tool: str, args: dict) -> tuple[Effect, Bind] | None:
    """Per-call override, or None to fall back to name-based typing."""
    if tool != "Bash":
        return None
    return classify_command(str((args or {}).get("command", "")))
