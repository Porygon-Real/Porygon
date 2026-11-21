"""Host-side normal-load drivers. They talk to the container only through its
loopback relay port, so they add no processes inside the monitored container.

A driver runs in a thread until stopped and counts successes and errors per
minute; the counts are recorded as they happen and are never adjusted.
"""
from __future__ import annotations

import random
import socket
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from typing import Any

from recipes import THROWAWAY_PASSWORD


class Driver(threading.Thread):
    interval = 0.5  # seconds between operations (about 2 per second)

    def __init__(self, port: int, recipe: dict[str, Any], seed: int):
        super().__init__(daemon=True)
        self.port, self.recipe = port, recipe
        self.rng = random.Random(seed)
        self.stop_event = threading.Event()
        self.per_minute: dict[int, dict[str, int]] = defaultdict(lambda: {"ok": 0, "error": 0})
        self.last_error = ""
        self.conn: Any = None

    def run(self) -> None:
        while not self.stop_event.is_set():
            minute = int(time.time() // 60)
            try:
                self.operation()
                self.per_minute[minute]["ok"] += 1
            except Exception as exc:  # noqa: BLE001 - a failed operation is recorded, then the driver reconnects
                self.per_minute[minute]["error"] += 1
                self.last_error = f"{type(exc).__name__}: {exc}"[:300]
                self.reset()
                self.stop_event.wait(1.0)
            self.stop_event.wait(self.interval)
        self.reset()

    def reset(self) -> None:
        try:
            if self.conn is not None:
                self.conn.close()
        except Exception:  # noqa: BLE001
            pass
        self.conn = None

    def stop(self) -> None:
        self.stop_event.set()
        self.join(timeout=15)

    def summary(self) -> dict[str, Any]:
        return {"per_minute": {str(k): v for k, v in sorted(self.per_minute.items())}, "last_error": self.last_error,
                "ok": sum(v["ok"] for v in self.per_minute.values()),
                "error": sum(v["error"] for v in self.per_minute.values())}

    def operation(self) -> None:
        raise NotImplementedError


class HttpDriver(Driver):
    def operation(self) -> None:
        path = self.rng.choice(self.recipe.get("paths", ["/"]))
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=10) as response:
                response.read()
        except urllib.error.HTTPError as exc:
            if exc.code >= 500:
                raise


class RedisDriver(Driver):
    def _cmd(self, *parts: str) -> bytes:
        if self.conn is None:
            self.conn = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        payload = f"*{len(parts)}\r\n" + "".join(f"${len(p)}\r\n{p}\r\n" for p in parts)
        self.conn.sendall(payload.encode())
        reply = self.conn.recv(65536)
        if not reply or reply.startswith(b"-"):
            raise RuntimeError(f"redis reply {reply[:80]!r}")
        return reply

    def operation(self) -> None:
        key = f"rt:key:{self.rng.randint(1, 200)}"
        choice = self.rng.random()
        if choice < 0.4:
            self._cmd("SET", key, str(self.rng.randint(0, 10**6)))
        elif choice < 0.8:
            self._cmd("GET", key)
        elif choice < 0.9:
            self._cmd("INCR", "rt:counter")
        else:
            self._cmd("LPUSH", "rt:list", str(time.time()))
            self._cmd("LTRIM", "rt:list", "0", "99")


class MemcachedDriver(Driver):
    def _send(self, text: str) -> bytes:
        if self.conn is None:
            self.conn = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        self.conn.sendall(text.encode())
        reply = self.conn.recv(65536)
        if not reply or reply.startswith((b"ERROR", b"SERVER_ERROR", b"CLIENT_ERROR")):
            raise RuntimeError(f"memcached reply {reply[:80]!r}")
        return reply

    def operation(self) -> None:
        key = f"rtkey{self.rng.randint(1, 200)}"
        if self.rng.random() < 0.4:
            value = str(self.rng.randint(0, 10**6))
            self._send(f"set {key} 0 600 {len(value)}\r\n{value}\r\n")
        else:
            self._send(f"get {key}\r\n")


class MysqlDriver(Driver):
    def operation(self) -> None:
        import pymysql  # project .venv
        if self.conn is None:
            self.conn = pymysql.connect(host="127.0.0.1", port=self.port, user="root", password=THROWAWAY_PASSWORD,
                                        database=self.recipe.get("env", {}).get("MARIADB_DATABASE")
                                        or self.recipe.get("env", {}).get("MYSQL_DATABASE"),
                                        connect_timeout=5, read_timeout=10, write_timeout=10, autocommit=True)
            with self.conn.cursor() as cur:
                cur.execute("create table if not exists rt_items (id int auto_increment primary key, v int, t timestamp default current_timestamp)")
        with self.conn.cursor() as cur:
            if self.rng.random() < 0.4:
                cur.execute("insert into rt_items (v) values (%s)", (self.rng.randint(0, 10**6),))
            else:
                cur.execute("select count(*), max(v) from rt_items where id > %s", (self.rng.randint(0, 500),))
                cur.fetchall()


class MongoDriver(Driver):
    def operation(self) -> None:
        import pymongo  # project .venv
        if self.conn is None:
            self.conn = pymongo.MongoClient("127.0.0.1", self.port, serverSelectionTimeoutMS=5000,
                                            directConnection=True)
        items = self.conn["porygon_rt"]["items"]
        if self.rng.random() < 0.4:
            items.insert_one({"v": self.rng.randint(0, 10**6), "t": time.time()})
        else:
            list(items.find({"v": {"$gt": self.rng.randint(0, 10**6)}}).limit(5))


class AmqpDriver(Driver):
    def operation(self) -> None:
        import pika  # project .venv
        if self.conn is None:
            params = pika.ConnectionParameters("127.0.0.1", self.port, socket_timeout=5, blocked_connection_timeout=10)
            self.conn = pika.BlockingConnection(params)
            self.channel = self.conn.channel()
            self.channel.queue_declare("porygon_rt", durable=True)
        if self.rng.random() < 0.5:
            self.channel.basic_publish("", "porygon_rt", str(time.time()).encode())
        else:
            self.channel.basic_get("porygon_rt", auto_ack=True)


class PostgresDriver(Driver):
    def operation(self) -> None:
        import pg8000.native  # project .venv
        env = self.recipe.get("env", {})
        if self.conn is None:
            self.conn = pg8000.native.Connection(
                user=env.get("POSTGRES_USER", "postgres"), password=env.get("POSTGRES_PASSWORD"),
                host="127.0.0.1", port=self.port, database=env.get("POSTGRES_DB", "postgres"), timeout=10)
            self.conn.run("create table if not exists rt_items (id serial primary key, v integer, "
                          "t timestamptz default now())")
        if self.rng.random() < 0.4:
            self.conn.run("insert into rt_items (v) values (:v)", v=self.rng.randint(0, 10**6))
        else:
            self.conn.run("select count(*), max(v) from rt_items where id > :i", i=self.rng.randint(0, 500))


class MqttDriver(Driver):
    """MQTT 3.1.1 over a raw socket: CONNECT once, then PUBLISH (QoS 0) and PINGREQ."""

    def _connect(self) -> None:
        self.conn = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        client_id = f"porygon-rt-{self.rng.randint(1, 10**6)}".encode()
        payload = b"\x00\x04MQTT\x04\x02\x00\x3c" + len(client_id).to_bytes(2, "big") + client_id
        self.conn.sendall(b"\x10" + bytes([len(payload)]) + payload)
        ack = self.conn.recv(4)
        if len(ack) < 4 or ack[0] != 0x20 or ack[3] != 0x00:
            raise RuntimeError(f"mqtt connack {ack!r}")

    def operation(self) -> None:
        if self.conn is None:
            self._connect()
        if self.rng.random() < 0.6:
            topic = f"porygon/rt/{self.rng.randint(1, 20)}".encode()
            body = str(self.rng.randint(0, 10**6)).encode()
            packet = len(topic).to_bytes(2, "big") + topic + body
            self.conn.sendall(b"\x30" + bytes([len(packet)]) + packet)
        else:
            self.conn.sendall(b"\xc0\x00")
            resp = self.conn.recv(2)
            if resp[:1] != b"\xd0":
                raise RuntimeError(f"mqtt pingresp {resp!r}")


class NatsDriver(Driver):
    """The NATS text protocol over a raw socket: CONNECT, then PUB and PING.

    A NATS server sends its own PING every couple of minutes and closes a client
    that leaves two of them unanswered, so the driver replies PONG to every
    server PING it sees. Without that the server's PING arrived where the
    driver's own PONG was expected and the connection was dropped repeatedly.
    """

    def _answer_server_pings(self, data: bytes) -> None:
        if b"PING\r\n" in data:
            self.conn.sendall(b"PONG\r\n")

    def _drain(self) -> None:
        """Read whatever the server has sent, answering its PINGs, without blocking."""
        self.conn.setblocking(False)
        data = b""
        try:
            while True:
                try:
                    chunk = self.conn.recv(65536)
                except (BlockingIOError, InterruptedError):
                    break
                if not chunk:
                    raise RuntimeError("nats closed the connection")
                data += chunk
        finally:
            self.conn.settimeout(5)
        self._answer_server_pings(data)

    def _connect(self) -> None:
        self.conn = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        info = self.conn.recv(65536)
        if not info.startswith(b"INFO "):
            raise RuntimeError(f"nats greeting {info[:80]!r}")
        self.conn.sendall(b'CONNECT {"verbose":false,"pedantic":false,"tls_required":false,"name":"porygon-rt"}\r\n'
                          b"PING\r\n")
        self._await_pong()

    def _await_pong(self) -> None:
        deadline = time.monotonic() + 5
        buffer = b""
        while b"PONG" not in buffer:
            if time.monotonic() > deadline:
                raise RuntimeError(f"nats sent no PONG within 5s (saw {buffer[:80]!r})")
            chunk = self.conn.recv(65536)
            if not chunk:
                raise RuntimeError("nats closed the connection")
            buffer += chunk
            self._answer_server_pings(chunk)

    def operation(self) -> None:
        if self.conn is None:
            self._connect()
        self._drain()
        if self.rng.random() < 0.6:
            subject = f"porygon.rt.{self.rng.randint(1, 20)}".encode()
            body = str(self.rng.randint(0, 10**6)).encode()
            self.conn.sendall(b"PUB " + subject + b" " + str(len(body)).encode() + b"\r\n" + body + b"\r\n")
        else:
            self.conn.sendall(b"PING\r\n")
            self._await_pong()


DRIVERS = {"http": HttpDriver, "redis": RedisDriver, "memcached": MemcachedDriver, "mysql": MysqlDriver,
           "mongo": MongoDriver, "amqp": AmqpDriver, "postgres": PostgresDriver, "mqtt": MqttDriver,
           "nats": NatsDriver}


def make_driver(recipe: dict[str, Any], port: int, seed: int) -> Driver:
    return DRIVERS[recipe["driver"]](port, recipe, seed)


def ping(recipe: dict[str, Any], port: int) -> bool:
    """One driver operation, used to confirm the service answers through the relay."""
    driver = make_driver(recipe, port, seed=0)
    try:
        driver.operation()
        return True
    except Exception:  # noqa: BLE001
        return False
    finally:
        driver.reset()
