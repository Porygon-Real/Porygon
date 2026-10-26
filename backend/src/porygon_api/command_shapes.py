"""Bounded command descriptors with a fixed vocabulary and no argument values.

This is a syntax feature extractor, not a shell interpreter. It never evaluates
expansions, reads referenced files, resolves URLs, or executes captured commands.
"""

from __future__ import annotations

import shlex
from collections import Counter
from urllib.parse import urlsplit

MAX_COMMAND_CHARS = 32768
MAX_TOKENS = 256
MAX_SHELL_DEPTH = 2
SHELL_COMMAND_FLAGS = frozenset({"-c", "-lc", "-ic", "-xc", "-ec", "--command"})
SHELLS = frozenset({"sh", "ash", "bash", "dash", "zsh", "ksh", "fish"})
PROGRAMS = SHELLS | frozenset(
    {
        "curl",
        "wget",
        "nc",
        "netcat",
        "ncat",
        "socat",
        "python",
        "python3",
        "perl",
        "ruby",
        "node",
        "php",
        "chmod",
        "chown",
        "sudo",
        "su",
        "nsenter",
        "unshare",
        "mount",
        "cat",
        "echo",
        "printf",
        "env",
        "busybox",
        "toybox",
        "tar",
        "base64",
        "openssl",
        "ssh",
        "scp",
        "find",
        "id",
        "whoami",
        "uname",
        "ls",
        "sleep",
    }
)
# Unknown flag names are opaque: even a flag name can contain a credential.
FLAGS = SHELL_COMMAND_FLAGS | frozenset(
    {
        "-c",
        "-e",
        "-m",
        "-i",
        "-l",
        "-s",
        "-f",
        "-k",
        "-d",
        "-o",
        "-O",
        "-L",
        "-X",
        "-H",
        "-A",
        "-u",
        "-p",
        "-q",
        "-n",
        "-r",
        "-v",
        "-x",
        "-w",
        "-S",
        "-fsSL",
        "-sSL",
        "-sS",
        "-fsS",
        "--help",
        "--version",
        "--url",
        "--request",
        "--header",
        "--data",
        "--data-binary",
        "--output",
        "--location",
        "--silent",
        "--fail",
        "--insecure",
        "--user",
        "--password",
        "--token",
        "--proxy",
        "--upload-file",
        "--execute",
        "--decode",
        "--connect-timeout",
        "--max-time",
    }
)
OPERATORS = frozenset({"|", "||", "&&", ";", "&", ">", ">>", "<", "<<", "(", ")"})
CONTRACT = {
    "argument_values": "fixed-categories-only",
    "unknown_flags": "opaque",
    "shell_payload": "bounded-syntax-only",
    "max_command_chars": MAX_COMMAND_CHARS,
    "max_tokens": MAX_TOKENS,
    "max_shell_depth": MAX_SHELL_DEPTH,
    "programs": sorted(PROGRAMS),
    "flags": sorted(FLAGS),
    "operators": sorted(OPERATORS),
}


def _value_shape(value: str) -> str:
    # No source string or hash of a source string is returned. Hashing secrets
    # would still permit dictionary attacks on low-entropy credentials.
    if value.startswith(("http://", "https://", "ftp://")):
        try:
            scheme = urlsplit(value).scheme
        except ValueError:
            return "value:url"
        return "value:url:" + scheme
    if value.startswith("/dev/tcp/"):
        return "value:socket-path"
    if value.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
        return "value:temporary-path"
    if value.startswith("/proc/"):
        return "value:proc-path"
    if value.startswith("/"):
        return "value:absolute-path"
    if value.isdecimal():
        return "value:number"
    if value.startswith("-"):
        return "value:opaque-option"
    return "value:opaque"


def command_shape_counts(command_line: str | None, *, depth: int = 0) -> Counter[str]:
    if not command_line or not command_line.strip():
        return Counter()
    if len(command_line) > MAX_COMMAND_CHARS:
        return Counter({"syntax:oversized": 1})
    if depth > MAX_SHELL_DEPTH:
        return Counter({"syntax:nesting-limit": 1})
    lexer = shlex.shlex(command_line, posix=False, punctuation_chars="|&;<>(" + ")")
    lexer.whitespace_split = True
    lexer.commenters = ""
    tokens: list[str] = []
    try:
        for token in lexer:
            if len(tokens) >= MAX_TOKENS:
                return Counter({"syntax:token-limit": 1})
            tokens.append(token)
    except ValueError:
        return Counter({"syntax:malformed": 1})
    if not tokens:
        return Counter()
    counts: Counter[str] = Counter()
    program = ""
    command_position = True
    shell_payload = False
    opaque_value = False
    for token in tokens:
        quoted = len(token) >= 2 and token[0] in {"'", '"'} and token[-1] == token[0]
        if quoted:
            try:
                values = shlex.split(token)
                if len(values) != 1:
                    return Counter({"syntax:malformed": 1})
                token = values[0]
            except ValueError:
                return Counter({"syntax:malformed": 1})
        if shell_payload:
            counts["syntax:inline-shell"] += 1
            counts.update(command_shape_counts(token, depth=depth + 1))
            shell_payload = False
            continue
        if opaque_value:
            counts[_value_shape(token)] += 1
            opaque_value = False
            continue
        if not quoted and token in OPERATORS:
            counts["operator:" + token] += 1
            command_position = token in {"|", "||", "&&", ";", "&", "("}
            continue
        if command_position:
            program = token.rsplit("/", 1)[-1]
            counts["program:" + (program if program in PROGRAMS else "opaque")] += 1
            command_position = False
            continue
        if program in {"busybox", "toybox"} and token in PROGRAMS:
            counts["syntax:multicall"] += 1
            program = token
            counts["program:" + program] += 1
            continue
        flag, separator, value = token.partition("=")
        if flag in FLAGS:
            counts["flag:" + flag] += 1
            if separator:
                counts[_value_shape(value)] += 1
            elif program in SHELLS and flag in SHELL_COMMAND_FLAGS:
                shell_payload = True
            elif flag in {"--header", "-H", "--user", "-u", "--password", "--token", "-A"}:
                opaque_value = True
        else:
            counts[_value_shape(token)] += 1
    return counts
