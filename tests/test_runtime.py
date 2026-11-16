"""Supervisor behavior against a real local DB and fake, non-network generators."""

import asyncio
import copy
import time

import pytest

from tvcas import runtime as runtime_module
from tvcas.runtime import Runtime
from tvcas.storage import Store


@pytest.fixture
def environment(tmp_path, monkeypatch):
    created = {"ecmg": [], "emmg": []}

    class FakeECMG:
        def __init__(self, config, log_callback=None):
            self.config = copy.deepcopy(config)
            self.started = self.closed = self.reloaded = 0
            created["ecmg"].append(self)

        async def start(self):
            self.started += 1

        async def close(self):
            self.closed += 1

        def status(self):
            return {"state": "running" if self.started and not self.closed else "stopped"}

        def diagnostics(self, peer_id=None, limit=100):
            return {"running": not self.closed, "peers": [], "retention_limit": 1000,
                    "entries": [{"peer_id": peer_id or "synthetic-peer", "cw1": "11" * 8,
                                 "cw2": "22" * 8, "limit_received": limit}]}

    class FakeEMMG(FakeECMG):
        def __init__(self, config, cards, *, timezone_offset_minutes=0, log_callback=None):
            self.config = copy.deepcopy(config)
            self.cards = cards
            self.timezone_offset_minutes = timezone_offset_minutes
            self.started = self.closed = self.reloaded = 0
            created["emmg"].append(self)

        def reload_cards(self):
            self.reloaded += 1

    monkeypatch.setattr(runtime_module, "ECMGServer", FakeECMG)
    monkeypatch.setattr(runtime_module, "EMMGClient", FakeEMMG)
    store = Store(tmp_path / "runtime.sqlite")
    store.save_row("ecmg", {"host": 2130706433, "port": 42000, "key": "a1" * 32,
                             "enable": 1, "status": 1})
    store.save_row("emmg", {"host": "127.0.0.1", "port": 41000, "enable": 1, "status": 1})
    store.save_row("cards", {"serial_no": 10001, "key": "b2" * 16,
                              "start": 1700000000, "finish": 2000000000})
    return store, created


@pytest.mark.parametrize("activation,enabled", [(False, False), (False, True), (True, False), (True, True)])
def test_activation_requires_both_independent_gates(environment, activation, enabled):
    store, created = environment
    store.set_settings({"runtime_enabled": enabled})
    runner = Runtime(store, activation_allowed=activation)
    asyncio.run(runner._reconcile())
    should_run = activation and enabled
    assert len(created["ecmg"]) == len(created["emmg"]) == int(should_run)
    assert runner.status()["state"] == ("active" if should_run else "offline")
    assert runner.status()["runtime_enabled"] is enabled
    # Migration/introspection must preserve desired saved generator enable flags.
    assert store.get_row("ecmg", 1)["enable"] == 1
    assert store.get_row("emmg", 1)["enable"] == 1


def test_enable_stop_restart_using_same_database(environment):
    store, created = environment
    runner = Runtime(store, activation_allowed=True)

    async def scenario():
        await runner._reconcile()
        assert created == {"ecmg": [], "emmg": []}
        # Simulate the web process opening a separate Store for the same DB.
        editor = Store(store.path)
        editor.set_settings({"runtime_enabled": True})
        await runner._reconcile()
        await runner._reconcile()
        assert [len(created[k]) for k in ("ecmg", "emmg")] == [1, 1]
        assert created["ecmg"][0].config["bind_host"] == "127.0.0.1"
        editor.set_settings({"runtime_enabled": False})
        await runner._reconcile()
        assert runner.status()["state"] == "offline"
        assert all(items[0].closed == 1 for items in created.values())
        assert runner.status()["ecmg"] == runner.status()["emmg"] == []
        editor.set_settings({"runtime_enabled": True})
        await runner._reconcile()
        assert all(len(items) == 2 and items[1].started == 1 for items in created.values())
        editor.set_settings({"runtime_enabled": False})
        await runner._reconcile()

    asyncio.run(scenario())


def test_real_config_change_restarts_only_affected_generator_once(environment):
    store, created = environment
    store.set_settings({"runtime_enabled": True})
    runner = Runtime(store, activation_allowed=True)

    async def scenario():
        await runner._reconcile()
        store.save_row("ecmg", {"delay_stop": 6000}, 1)
        await runner._reconcile()
        await runner._reconcile()
        assert len(created["ecmg"]) == 2
        assert created["ecmg"][0].closed == 1
        assert created["ecmg"][1].started == 1
        assert created["ecmg"][1].config["delay_stop"] == 6000
        assert len(created["emmg"]) == 1 and created["emmg"][0].closed == 0
        # Legacy bookkeeping updates do not interrupt active transports.
        store.save_row("ecmg", {"touch_time": 50, "touch_version": 40, "version": 40}, 1)
        await runner._reconcile()
        assert len(created["ecmg"]) == 2
        store.set_settings({"runtime_enabled": False})
        await runner._reconcile()

    asyncio.run(scenario())


def test_card_edit_refreshes_emm_without_ecm_restart(environment):
    store, created = environment
    store.set_settings({"runtime_enabled": True})
    runner = Runtime(store, activation_allowed=True)

    async def scenario():
        await runner._reconcile()
        store.save_row("cards", {"access_criteria": "00000081"}, 1)
        await runner._reconcile()
        await runner._reconcile()
        assert len(created["ecmg"]) == len(created["emmg"]) == 1
        assert created["ecmg"][0].closed == 0
        assert created["emmg"][0].reloaded == 1
        assert created["emmg"][0].cards()[0]["access_criteria"] == "00000081"
        # Configured date zone affects EMM payloads and therefore the EMMG only.
        store.set_settings({"zone": "+0200"})
        await runner._reconcile()
        assert len(created["ecmg"]) == 1
        assert len(created["emmg"]) == 2
        assert created["emmg"][1].timezone_offset_minutes == 120
        store.set_settings({"runtime_enabled": False})
        await runner._reconcile()

    asyncio.run(scenario())


def test_disabled_or_deleted_generator_is_stopped_independently(environment):
    store, created = environment
    store.set_settings({"runtime_enabled": True})
    runner = Runtime(store, activation_allowed=True)

    async def scenario():
        await runner._reconcile()
        store.save_row("ecmg", {"enable": 0}, 1)
        await runner._reconcile()
        assert created["ecmg"][0].closed == 1
        assert created["emmg"][0].closed == 0
        assert runner.status()["ecmg"] == []
        store.save_row("emmg", {"d_id": 9}, 1)
        await runner._reconcile()
        assert created["emmg"][0].closed == 1
        assert runner.status()["emmg"] == []

    asyncio.run(scenario())


def test_shutdown_joins_worker_and_closes_every_generator(environment):
    store, created = environment
    store.set_settings({"runtime_enabled": True})
    runner = Runtime(store, activation_allowed=True)
    runner.start()
    worker = runner._thread
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and len(runner.status()["emmg"]) != 1:
            time.sleep(0.005)
        assert len(runner.status()["ecmg"]) == len(runner.status()["emmg"]) == 1
        # Readers receive a copy, so a UI cannot mutate runtime's status.
        altered = runner.status()
        altered["ecmg"].clear()
        assert len(runner.status()["ecmg"]) == 1
    finally:
        runner.close()
    assert not worker.is_alive()
    assert all(items[0].closed == 1 for items in created.values())
    assert runner.status()["state"] == "offline"
    assert runner.status()["ecmg"] == runner.status()["emmg"] == []
    runner.close()  # Idempotent after shutdown.


def test_private_diagnostics_are_requested_on_demand_and_absent_when_offline(environment):
    store, created = environment
    runner = Runtime(store, activation_allowed=True)
    assert runner.ecmg_diagnostics(1)["state"] == "offline"
    store.set_settings({"runtime_enabled": True})
    runner.start()
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not runner.status()["ecmg"]:
            time.sleep(0.005)
        diagnostic = runner.ecmg_diagnostics(1, peer_id="chosen-peer", limit=100000)
        assert diagnostic["state"] == "active"
        assert diagnostic["generator_id"] == 1
        assert diagnostic["entries"][0]["peer_id"] == "chosen-peer"
        assert diagnostic["entries"][0]["limit_received"] == 1000
        assert diagnostic["entries"][0]["cw1"] == "11" * 8
        assert "cw1" not in str(runner.status())
        assert runner.ecmg_diagnostics(999)["state"] == "offline"
        # Taking private snapshots neither restarts nor reconfigures generators.
        assert len(created["ecmg"]) == 1 and created["ecmg"][0].started == 1
        assert created["ecmg"][0].closed == 0
    finally:
        runner.close()
    assert runner.ecmg_diagnostics(1)["entries"] == []
    assert runner.ecmg_diagnostics(1)["state"] == "offline"
