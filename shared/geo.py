"""Geolocalização aproximada: sempre usa o IP observado pelo servidor.

Para endereços públicos, exige o arquivo oficial IP2Location LITE DB11.BIN.
Endereços de loopback são marcados explicitamente como ambiente local.
"""

import ipaddress
from pathlib import Path

DB_FILE = Path(__file__).resolve().parents[1] / "data" / "ip2location" / "IP2LOCATION-LITE-DB11.BIN"


class GeoError(ValueError):
    pass


def lookup_ip(ip: str) -> dict:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise GeoError("Endereço IP inválido.") from exc

    if address.is_loopback:
        return {"ip": ip, "country": "LOCAL", "region": "LOCAL", "city": "LOCAL",
                "latitude": None, "longitude": None, "asn": None, "source": "LOOPBACK"}

    # IPs privados, de documentação e reservados não possuem geolocalização pública.
    if not address.is_global:
        raise GeoError("Este IP não é público nem loopback; não pode ser geolocalizado.")
    if not DB_FILE.is_file():
        raise GeoError("Arquivo IP2Location ausente. Instale o banco LITE DB11.BIN (veja README).")

    try:
        import IP2Location
        reader = IP2Location.IP2Location(str(DB_FILE))
        result = reader.get_all(ip)
    except (ImportError, OSError) as exc:
        raise GeoError("Não foi possível abrir o banco IP2Location.") from exc

    def clean(value):
        if value is None or str(value).upper().startswith(("NOT SUPPORTED", "INVALID IP", "-")):
            return None
        return value

    country = clean(result.country_short)
    if not country or country == "-":
        raise GeoError("O IP2Location não retornou um país válido para este IP.")

    return {
        "ip": ip,
        "country": country,
        "region": clean(result.region),
        "city": clean(result.city),
        "latitude": clean(result.latitude),
        "longitude": clean(result.longitude),
        "asn": clean(getattr(result, "asn", None)),
        "organization": clean(getattr(result, "as_name", None)) or clean(getattr(result, "isp", None)),
        "source": "IP2LOCATION",
    }


def same_location(actual: dict, claimed: dict) -> bool:
    """Compara contexto (sem confiar em coordenadas fornecidas pelo cliente)."""
    return all(actual.get(k) == claimed.get(k)
               for k in ("ip", "country", "region", "city", "source"))
