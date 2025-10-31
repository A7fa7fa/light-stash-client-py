from collections.abc import Generator
import queue
import threading
import time
from contextlib import contextmanager
from typing import Any

from .exception import LightStashError
from .lightstash_client import LightStashClient


class PooledConnection:
    """Wrapper that tracks last usage time."""

    def __init__(self, client: LightStashClient):
        self.client = client
        self.last_used = time.monotonic()

    def touch(self) -> None:
        self.last_used = time.monotonic()


class LightStashConnectionPool:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1234,
        sock_timeout: float = 2.0,
        max_connections: int = 10,
        idle_timeout: int = 60,
        health_check_interval: int = 30,
        use_tls: bool = False,
        cafile: str | None = None,
    ):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.cafile = cafile
        self.sock_timeout = sock_timeout
        self.max_connections = max_connections
        self.idle_timeout = idle_timeout
        self.health_check_interval = health_check_interval

        self._pool: queue.Queue[PooledConnection] = queue.Queue(max_connections)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._health_thread = threading.Thread(
            target=self._health_check_loop, daemon=True
        )

        for _ in range(max_connections):
            client = LightStashClient(
                host=self.host,
                port=self.port,
                use_tls=self.use_tls,
                cafile=self.cafile,
                sock_timeout=self.sock_timeout,
            )
            try:
                client.connect()
            except Exception:
                pass
            self._pool.put(PooledConnection(client))

        self._health_thread.start()

    def _get(self) -> PooledConnection:
        conn = self._pool.get()

        if not conn.client.sock:
            try:
                conn.client.connect()
            except Exception as e:
                raise LightStashError(f"Failed to reconnect: {e}")
        conn.touch()
        return conn

    def _release(self, conn: PooledConnection) -> None:
        conn.touch()
        self._pool.put(conn)

    @contextmanager
    def connection(self) -> Generator[LightStashClient, Any, Any]:
        conn = self._get()
        try:
            yield conn.client
        finally:
            self._release(conn)

    def _health_check_loop(self) -> None:
        """Background thread that removes idle or dead connections."""
        while not self._stop_event.is_set():
            time.sleep(self.health_check_interval)
            now = time.monotonic()
            new_pool: queue.Queue[PooledConnection] = queue.Queue(self.max_connections)
            # Drain pool to inspect connections
            while not self._pool.empty():
                conn = self._pool.get_nowait()
                age = now - conn.last_used
                if age > self.idle_timeout:
                    conn.client.disconnect()
                    continue
                try:
                    if not conn.client.ping():
                        conn.client.disconnect()
                        conn.client.connect()
                except Exception:
                    conn.client.disconnect()
                    try:
                        conn.client.connect()
                    except Exception:
                        pass
                new_pool.put(conn)
            self._pool = new_pool

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_all()

    def close_all(self) -> None:
        """Gracefully close all connections and stop the health thread."""
        self._stop_event.set()
        self._health_thread.join(timeout=2.0)
        while not self._pool.empty():
            c = self._pool.get_nowait()
            c.client.disconnect()
