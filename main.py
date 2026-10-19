"""Inicia loja, gateway e cliente: python main.py [--local]."""

import argparse
from getpass import getpass
import multiprocessing as mp
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time

import httpx

ROOT = Path(__file__).resolve().parent


def run_service(name, channel, stop, data_dir):
    """O filho recebe as frases por pipe e usa um banco próprio."""
    import uvicorn

    try:
        config = channel.recv()
        if name == "store":
            from store.main import app
            from store import database
            from store.security import init_or_verify_master_passphrase
        else:
            from gateway.main import app
            from gateway import database
        database.DB_PATH = Path(data_dir) / f"{name}.db"
        database.init_db()
        app.state.payment_passphrase = config["payment"]
        if name == "store":
            init_or_verify_master_passphrase(config["master"])
            app.state.master_passphrase = config["master"]
            app.state.tunnel_host = config["tunnel_host"]
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 8000 if name == "store" else 8001))
            server = uvicorn.Server(uvicorn.Config(
                app, log_level="error", access_log=False, proxy_headers=False))

            def shutdown():
                stop.wait()
                server.should_exit = True

            threading.Thread(target=shutdown, daemon=True).start()
            channel.send(None)  # A porta está reservada; o HTTP será verificado depois.
            server.run(sockets=[sock])
    except Exception as exc:
        channel.send(str(exc))
    finally:
        channel.close()


def start_service(name, config, stop, data_dir=ROOT / "data"):
    context = mp.get_context("spawn")
    parent, child = context.Pipe()
    process = context.Process(target=run_service, args=(name, child, stop, data_dir))
    process.start()
    child.close()
    try:
        parent.send(config)
        if not parent.poll(30):
            raise RuntimeError(f"Tempo esgotado ao iniciar {name}.")
        error = parent.recv()
        if error:
            raise RuntimeError(f"Falha em {name}: {error}")
        return process
    except BaseException:
        process.terminate()
        process.join()
        process.close()
        raise
    finally:
        parent.close()


def stop_services(processes, stop):
    stop.set()
    for process in reversed(processes):
        process.join(timeout=5)
        if process.is_alive():
            process.terminate()
            process.join()
        process.close()


def read_tunnel_url(tunnel):
    urls = queue.Queue()

    def read_output():
        for line in tunnel.stdout:
            match = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com\b", line)
            if match:
                urls.put(match.group())
        urls.put(None)

    threading.Thread(target=read_output, daemon=True).start()
    try:
        url = urls.get(timeout=60)
    except queue.Empty as exc:
        raise RuntimeError("O túnel não forneceu uma URL em 60 segundos.") from exc
    if not url:
        raise RuntimeError("O túnel não iniciou. Confira a conexão com a Internet.")
    return url


def wait_for_store(processes, tunnel=None):
    from client import api

    with api.http_client() as client:
        for _ in range(20):
            if any(not process.is_alive() for process in processes):
                raise RuntimeError("Um serviço foi encerrado durante a inicialização.")
            if tunnel is not None and tunnel.poll() is not None:
                raise RuntimeError("O túnel foi encerrado durante a inicialização.")
            try:
                if client.get("/docs", timeout=5).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(.5)
    raise RuntimeError("A loja não ficou acessível.")


def main():
    parser = argparse.ArgumentParser(description="Loja virtual segura")
    parser.add_argument("--local", action="store_true", help="Executa sem túnel e sem IP público")
    args = parser.parse_args()
    stop = mp.get_context("spawn").Event()
    processes, tunnel = [], None
    try:
        from shared.geo import DB_FILE
        executable = ROOT / ".tools" / ("cloudflared.exe" if os.name == "nt" else "cloudflared")
        executable = str(executable) if executable.is_file() else shutil.which("cloudflared")
        if not args.local and (not executable or not DB_FILE.is_file()):
            raise RuntimeError("Instale cloudflared e a base DB11 conforme o README.")
        master = getpass("Frase-mestra da loja (mínimo 16 caracteres): ")
        payment = getpass("Frase loja-gateway (mínimo 16 caracteres): ")
        if len(master) < 16 or len(payment) < 16:
            raise ValueError("As frases precisam ter pelo menos 16 caracteres.")
        origin = None if args.local else secrets.token_hex(24) + ".internal"
        print("Iniciando loja e gateway...", flush=True)
        processes.append(start_service("store", {"master": master, "payment": payment,
                                                 "tunnel_host": origin}, stop))
        processes.append(start_service("gateway", {"payment": payment}, stop))
        url = "http://127.0.0.1:8000"
        if not args.local:
            print("Conectando o túnel HTTPS...", flush=True)
            tunnel = subprocess.Popen(
                [executable, "tunnel", "--url", url, "--http-host-header", origin, "--no-autoupdate"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            url = read_tunnel_url(tunnel)
        from client import api
        from client.main import main as client_main
        api.configure(url)
        wait_for_store(processes, tunnel)
        print(f"Loja pronta: {url}", flush=True)
        client_main()
    except (RuntimeError, EOFError, OSError, ValueError) as exc:
        raise SystemExit(f"Erro: {exc}") from exc
    except KeyboardInterrupt:
        print("\nEncerrando...")
    finally:
        if tunnel is not None:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tunnel.kill()
                tunnel.wait()
            tunnel.stdout.close()
        stop_services(processes, stop)


if __name__ == "__main__":
    main()
