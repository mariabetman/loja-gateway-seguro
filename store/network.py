"""IP observado diretamente ou encaminhado por um Quick Tunnel local."""

import ipaddress
import secrets

from fastapi import HTTPException, Request


def observed_ip(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    tunnel_host = getattr(request.app.state, "tunnel_host", None)
    if tunnel_host is None:
        # No modo local, nenhum cabeçalho de proxy altera o IP.
        return peer

    try:
        local_proxy = ipaddress.ip_address(peer).is_loopback
    except ValueError:
        local_proxy = False
    hosts = request.headers.getlist("host")
    if (not local_proxy or len(hosts) != 1
            or not secrets.compare_digest(hosts[0].encode("utf-8"), tunnel_host.encode("utf-8"))):
        raise HTTPException(403, "Acesso permitido somente pelo túnel configurado.")

    ips = request.headers.getlist("cf-connecting-ip")
    protocols = request.headers.getlist("x-forwarded-proto")
    if len(ips) != 1 or protocols != ["https"]:
        raise HTTPException(400, "Contexto HTTPS/IP do túnel ausente ou inválido.")
    try:
        address = ipaddress.ip_address(ips[0])
    except ValueError as exc:
        raise HTTPException(400, "IP encaminhado inválido.") from exc
    if not address.is_global:
        raise HTTPException(400, "O túnel deve informar um IP público.")
    return str(address)
