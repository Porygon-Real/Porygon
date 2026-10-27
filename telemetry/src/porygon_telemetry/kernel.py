"""Normalize supported runtime syscalls without reclassifying them as execs."""

import hashlib
from ipaddress import ip_address
import json
import re

from porygon_telemetry.normalizer import _event_time, _nonnegative_int, _text

RULES = {
    "Porygon Container Outbound Connection": ("net_outbound", {"connect"}),
    "Porygon Container Memory Backed File": ("memfd_create", {"memfd_create"}),
    "Porygon Container Sensitive Write Open": ("file_write_open", {"open", "openat", "openat2"}),
    "Porygon Container Sensitive File Write": (
        "file_write",
        {"write", "writev", "pwrite", "pwritev"},
    ),
}


def normalize_kernel_event(raw_event, *, sensor_instance_id, reported_docker_host_id):
    rule = _text(raw_event.get("rule"), 255)
    if rule not in RULES or raw_event.get("source", "syscall") != "syscall":
        return None
    fields = raw_event.get("output_fields")
    if not isinstance(fields, dict):
        raise ValueError("Kernel output_fields must be an object")
    cid = _text(fields.get("container.id"), 128)
    if not cid or cid == "host":
        return None
    if re.fullmatch(r"[0-9a-f]{12,64}", cid) is None:
        # Falco can report host cgroup labels (for example system.slice).
        # They are outside this Docker-ID evidence stream, not malformed JSON.
        return None
    kind, types = RULES[rule]
    syscall = _text(fields.get("evt.type"), 64)
    if syscall not in types:
        raise ValueError("Kernel rule and syscall do not agree")
    try:
        result = int(fields["evt.rawres"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Kernel syscall return value is missing") from exc
    if result < 0 and not (kind == "net_outbound" and result == -115):
        return None
    if kind == "file_write" and result <= 0:
        return None
    nano, occurred = _event_time(raw_event, fields)
    pid = _nonnegative_int(fields.get("proc.pid"))
    if pid is None:
        raise ValueError("Kernel process PID is missing")
    remote = None
    remote_port = None
    local = None
    local_port = None
    if kind == "net_outbound":
        try:
            peer = ip_address(_text(fields.get("fd.rip")) or "")
        except ValueError as exc:
            raise ValueError("Outbound kernel event has no valid peer address") from exc
        if (
            peer.is_loopback
            or peer.is_unspecified
            or (getattr(peer, "ipv4_mapped", None) is not None and peer.ipv4_mapped.is_loopback)
        ):
            return None
        remote = str(peer)
        remote_port = _nonnegative_int(fields.get("fd.rport"))
        if remote_port is None or not 1 <= remote_port <= 65535:
            raise ValueError("Outbound kernel event has no valid peer port")
        local_text = _text(fields.get("fd.lip"))
        if local_text is not None:
            local = str(ip_address(local_text))
        local_port = _nonnegative_int(fields.get("fd.lport"))
    path = _text(fields.get("fd.name")) if kind in {"file_write_open", "file_write"} else None
    if kind in {"file_write_open", "file_write"} and not path:
        raise ValueError("Kernel file activity has no path")
    document = dict(
        sensor_instance_id=sensor_instance_id,
        time_nano=nano,
        event_number=_nonnegative_int(fields.get("evt.num")),
        event_type=syscall,
        runtime_action=kind,
        reported_container_id=cid,
        process_pid=pid,
        return_value=result,
        remote_address=remote,
        remote_port=remote_port,
        file_path=path,
        memory_name=_text(fields.get("evt.arg.name")) if kind == "memfd_create" else None,
    )
    event_id = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return dict(
        document,
        event_id=event_id,
        _event_channel="kernel",
        sensor_hostname=_text(raw_event.get("hostname"), 255),
        source="falco",
        rule_name=rule,
        priority=_text(raw_event.get("priority"), 32) or "Notice",
        occurred_at=occurred.isoformat(),
        reported_docker_host_id=reported_docker_host_id,
        process_name=_text(fields.get("proc.name"), 255),
        executable=_text(fields.get("proc.exepath")),
        command_line=_text(fields.get("proc.cmdline")),
        user_uid=_nonnegative_int(fields.get("user.uid")),
        local_address=local,
        local_port=local_port,
        output_fields=fields,
        raw_event=raw_event,
    )
