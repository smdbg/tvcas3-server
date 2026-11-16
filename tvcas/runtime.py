"""One event loop supervising all generators; no shell/cron process spawning."""
from __future__ import annotations

import asyncio
from concurrent.futures import Future, TimeoutError as FutureTimeoutError
import copy
import hashlib
import ipaddress
import json
import logging
import threading

from .ecmg import ECMGServer, ECM_LOG_LIMIT
from .emmg import EMMGClient

LOG = logging.getLogger(__name__)
TRANSIENT = {"touch_time", "touch_version", "peers", "channel_time_open", "stream_time_open",
             "error_time_last", "error_count", "datagram_time_last", "datagram_count",
             "queue_size", "reload", "reload_time", "m_time", "version"}


def zone_minutes(zone):
    if not isinstance(zone, str) or len(zone) != 5 or zone[0] not in "+-" or not zone[1:].isdigit():
        raise ValueError("Zone must be a fixed offset such as +0000")
    hours, minutes = int(zone[1:3]), int(zone[3:])
    if hours > 14 or minutes > 59 or (hours == 14 and minutes):
        raise ValueError("Invalid UTC offset")
    return (hours * 60 + minutes) * (-1 if zone[0] == "-" else 1)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).digest()


class Runtime:
    """Constructing or viewing a migrated app never implicitly starts output.

    Both explicit process activation and the saved runtime switch are required.
    Desired per-generator enable flags are preserved independently on import.
    """
    def __init__(self, store, *, activation_allowed=False):
        self.store = store
        self.activation_allowed = activation_allowed
        self._loop = None
        self._thread = None
        self._ready = threading.Event()
        self._state_lock = threading.Lock()
        self._services = {}
        self._errors = {}
        self._cards_fingerprint = None
        self._snapshot = {"activation_allowed": activation_allowed, "runtime_enabled": False,
                          "state": "offline", "ecmg": [], "emmg": []}

    def start(self):
        if self._thread:
            return
        self._ready.clear()
        self._loop = None
        self._thread = threading.Thread(target=self._thread_main, name="tvcas-runtime", daemon=True)
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("Generator supervisor did not start")

    def _thread_main(self):
        asyncio.run(self._main())

    async def _main(self):
        self._loop = asyncio.get_running_loop()
        self._changed = asyncio.Event()
        self._stop = asyncio.Event()
        self._ready.set()
        try:
            while not self._stop.is_set():
                self._changed.clear()
                try:
                    await self._reconcile()
                except Exception as exc:
                    LOG.error("Supervisor configuration check failed (%s)", type(exc).__name__)
                try:
                    await asyncio.wait_for(self._changed.wait(), timeout=10)
                except asyncio.TimeoutError:
                    pass
        finally:
            for _, service in self._services.values():
                await service.close()
            self._services.clear()
            self._publish(False)

    def reconcile(self):
        if self._loop and self._thread and self._thread.is_alive():
            self._loop.call_soon_threadsafe(self._changed.set)

    def close(self):
        if self._loop and self._thread and self._thread.is_alive():
            self._loop.call_soon_threadsafe(self._stop.set)
            self._loop.call_soon_threadsafe(self._changed.set)
            self._thread.join(timeout=15)
            if self._thread.is_alive():
                raise RuntimeError("Generator supervisor did not stop")
        self._thread = None
        self._loop = None

    def status(self):
        with self._state_lock:
            return copy.deepcopy(self._snapshot)

    def ecmg_diagnostics(self, generator_id, peer_id=None, limit=100):
        """Read the private journal on demand, without periodic CW snapshots.

        Web workers request a bounded copy from the generator's event loop.
        This does not read the database, reconfigure services or block ECM
        generation on I/O. A stopped/busy runtime returns an explicit state.
        """
        generator_id = int(generator_id)
        limit = min(ECM_LOG_LIMIT, max(1, int(limit)))
        empty = {"generator_id": generator_id, "running": False, "peers": [],
                 "entries": [], "retention_limit": ECM_LOG_LIMIT, "state": "offline"}

        def snapshot():
            service = self._services.get(("ecmg", generator_id))
            if service:
                return dict(service[1].diagnostics(peer_id=peer_id, limit=limit),
                            generator_id=generator_id, state="active")
            error = self._errors.get(("ecmg", generator_id))
            return dict(empty, state="error", error=error) if error else dict(empty)

        loop, thread = self._loop, self._thread
        if loop is None or thread is None or not thread.is_alive() or loop.is_closed():
            return empty
        if threading.current_thread() is thread:
            return snapshot()
        future = Future()

        def capture():
            if future.set_running_or_notify_cancel():
                try:
                    future.set_result(snapshot())
                except Exception:
                    # Do not propagate service/config representations to HTTP.
                    future.set_result(dict(empty, state="unavailable", error="ECMG diagnostics unavailable"))

        try:
            loop.call_soon_threadsafe(capture)
            return future.result(timeout=2)
        except (RuntimeError, FutureTimeoutError):
            future.cancel()
            return dict(empty, state="unavailable", error="ECMG diagnostics unavailable")

    def _publish(self, enabled):
        snapshot = {"activation_allowed": self.activation_allowed, "runtime_enabled": enabled,
                    "state": "active" if self.activation_allowed and enabled else "offline",
                    "ecmg": [], "emmg": []}
        for (kind, id), (_, service) in self._services.items():
            snapshot[kind].append(dict(id=id, **service.status()))
        for (kind, id), error in self._errors.items():
            snapshot[kind].append(dict(id=id, state="error", error=error))
        with self._state_lock:
            self._snapshot = snapshot

    async def _reconcile(self):
        settings = self.store.get_settings()
        enabled = bool(settings.get("runtime_enabled"))
        desired = {}
        if enabled and self.activation_allowed:
            for kind in ("ecmg", "emmg"):
                for row in self.store.list_rows("tvcas_" + kind):
                    if row.get("enable") and row.get("status") == 1 and not row.get("d_id", 0):
                        config = {k: v for k, v in row.items() if k not in TRANSIENT}
                        if kind == "emmg":
                            config["timezone_offset_minutes"] = zone_minutes(settings.get("zone", "+0000"))
                        desired[(kind, row["id"])] = config
        for key in list(self._services):
            signature, service = self._services[key]
            if key not in desired or fingerprint(desired[key]) != signature:
                await service.close()
                del self._services[key]
        self._errors = {k: v for k, v in self._errors.items() if k in desired}
        cards_signature = fingerprint(self.store.list_rows("tvcas_smartcards")) if desired else None
        for key, config in desired.items():
            kind, id = key
            if key in self._services:
                if kind == "emmg" and cards_signature != self._cards_fingerprint:
                    self._services[key][1].reload_cards()
                continue
            signature = fingerprint(config)
            try:
                if not 1 <= int(config.get("port", 0)) <= 65535:
                    raise ValueError("Generator port must be between 1 and 65535")
                callback = lambda message, k=kind, i=id: LOG.info("%s %d: %s", k.upper(), i, message)
                if kind == "ecmg":
                    config = dict(config)
                    config["bind_host"] = str(ipaddress.IPv4Address(int(config.get("host") or 0)))
                    service = ECMGServer(config, log_callback=callback)
                else:
                    service = EMMGClient(config, lambda: self.store.list_rows("tvcas_smartcards"),
                        timezone_offset_minutes=config["timezone_offset_minutes"], log_callback=callback)
                await service.start()
                self._services[key] = (signature, service)
                self._errors.pop(key, None)
            except (ValueError, OSError) as exc:
                # Known validation messages contain field names, never key material.
                self._errors[key] = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        self._cards_fingerprint = cards_signature
        self._publish(enabled)
