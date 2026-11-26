"""Bounded command descriptors with a fixed vocabulary and no argument values.

This is a syntax feature extractor, not a shell interpreter. It never evaluates
expansions, reads referenced files, resolves URLs, or executes captured commands.
"""

from __future__ import annotations

import shlex
from collections import Counter
from copy import deepcopy
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
OPERATORS = frozenset({"|", "||", "&&", ";", "&", ">", ">>", "<", "<<", "<<<", "(", ")"})
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

# Separate feature contract: CONTRACT and command_shape_counts are historical
# inputs to immutable profile hashes and must not change.
SUPPORT_AWARE_CONTRACT = {
    **deepcopy(CONTRACT),
    "descriptor_extension": "bounded-oov-option-form-and-argument-position-classes",
    "argument_position_buckets": ["early", "middle", "late"],
    "raw_argument_values": False,
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


def _clean_token(token: str) -> str:
    return token.replace("'", "").replace('"', "").replace("\\", "")


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
            if token == "<<<" and program in SHELLS:
                shell_payload = True
            command_position = token in {"|", "||", "&&", ";", "&", "("}
            continue
        if command_position:
            clean_token = _clean_token(token.rsplit("/", 1)[-1])
            program = clean_token if clean_token in PROGRAMS else token.rsplit("/", 1)[-1]
            counts["program:" + (clean_token if clean_token in PROGRAMS else "opaque")] += 1
            command_position = False
            continue
        if program in {"busybox", "toybox"}:
            clean_sub = _clean_token(token)
            if clean_sub in PROGRAMS:
                counts["syntax:multicall"] += 1
                program = clean_sub
                counts["program:" + program] += 1
                continue
        flag, separator, value = token.partition("=")
        clean_flag = _clean_token(flag)
        if clean_flag in FLAGS:
            counts["flag:" + clean_flag] += 1
            if separator:
                counts[_value_shape(value)] += 1
            elif program in SHELLS and clean_flag in SHELL_COMMAND_FLAGS:
                shell_payload = True
            elif clean_flag in {"--header", "-H", "--user", "-u", "--password", "--token", "-A"}:
                opaque_value = True
        else:
            counts[_value_shape(token)] += 1
    return counts


def command_shape_counts_support_aware(
    command_line: str | None, *, depth: int = 0
) -> Counter[str]:
    """Return bounded, value-free command descriptors for the newer contract.

    The legacy extractor stays untouched so old feature documents and hashes
    remain reproducible. The added descriptors distinguish broad argument
    order and out-of-vocabulary syntax classes without retaining values.
    """

    counts = command_shape_counts(command_line, depth=depth)
    if not counts or any(
        token
        in {
            "syntax:malformed",
            "syntax:oversized",
            "syntax:token-limit",
            "syntax:nesting-limit",
        }
        for token in counts
    ):
        return counts
    if not command_line or len(command_line) > MAX_COMMAND_CHARS:
        return counts
    try:
        tokens = shlex.split(command_line, posix=False)
    except ValueError:
        return counts
    if len(tokens) > MAX_TOKENS:
        return counts
    if tokens:
        executable = _clean_token(tokens[0].rsplit("/", 1)[-1])
        if executable not in PROGRAMS:
            counts["syntax:oov-program"] += 1
    argument_count = max(0, len(tokens) - 1)
    for index, token in enumerate(tokens[1:]):
        if argument_count <= 2 or index == 0:
            position = "early"
        elif index == argument_count - 1 or index >= 5:
            position = "late"
        else:
            position = "middle"
        flag, separator, value = token.partition("=")
        clean_flag = _clean_token(flag)
        if token.startswith("-") and clean_flag not in FLAGS:
            prefix = "long" if token.startswith("--") else "short"
            form = "assignment" if separator else "separate-value"
            counts[f"syntax:oov-option:{position}:{prefix}:{form}"] += 1
        else:
            # Only emit a broad value class; neither source text nor a digest
            # of a potentially sensitive argument is retained.
            value_class = _value_shape(value if separator else token)
            counts["argument:" + position + ":" + value_class] += 1
    return counts


def command_shape_coverage(command_line: str | None) -> tuple[Counter[str], str]:
    """Return new-contract descriptors and a safe evidence-coverage class."""

    if not command_line or not command_line.strip():
        return Counter(), "unavailable"
    counts = command_shape_counts_support_aware(command_line)
    if any(
        marker in counts
        for marker in (
            "syntax:malformed",
            "syntax:oversized",
            "syntax:token-limit",
            "syntax:nesting-limit",
        )
    ):
        return counts, "fallback"
    return counts, "usable" if counts else "fallback"
