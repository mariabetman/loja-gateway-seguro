"""Inicialização integrada com processos reais e bancos isolados."""

import socket
import multiprocessing as mp

import httpx
import pytest

from main import start_service, stop_services, wait_for_store


def test_services_start_in_independent_processes_and_stop(tmp_path, monkeypatch):
    stop = mp.get_context("spawn").Event()
    processes = []
    try:
        processes.append(start_service("store", {"master": "mestra-teste-integrado-2026",
                         "payment": "pagamento-teste-integrado-2026", "tunnel_host": None}, stop, tmp_path))
        processes.append(start_service("gateway", {"payment": "pagamento-teste-integrado-2026"}, stop, tmp_path))
        from client import api
        monkeypatch.setattr(api, "STORE_URL", "http://127.0.0.1:8000")
        wait_for_store(processes)
        assert len({p.pid for p in processes}) == 2
        with httpx.Client(trust_env=False) as client:
            assert client.get("http://127.0.0.1:8001/openapi.json").status_code == 200
        assert (tmp_path / "store.db").is_file()
        assert (tmp_path / "gateway.db").is_file()
    finally:
        stop_services(processes, stop)
    assert all(p._closed for p in processes)
    for port in (8000, 8001):
        with socket.socket() as connection:
            assert connection.connect_ex(("127.0.0.1", port)) != 0


def test_occupied_port_reports_error_and_cleans_child(tmp_path):
    stop = mp.get_context("spawn").Event()
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 8001))
        occupied.listen()
        with pytest.raises(RuntimeError, match="gateway"):
            start_service("gateway", {"payment": "pagamento-teste-integrado-2026"}, stop, tmp_path)


def test_client_gets_integrated_url_without_environment(monkeypatch):
    from client import api
    monkeypatch.setattr(api, "STORE_URL", "http://127.0.0.1:8000")
    api.configure("https://demo.trycloudflare.com")
    assert api.STORE_URL == "https://demo.trycloudflare.com"
