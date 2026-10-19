"""Geolocalização aproximada: sempre usa o IP observado pelo servidor.

Para endereços públicos, utiliza a base oficial IP2Location LITE DB11 BIN.
Endereços de loopback são marcados explicitamente como ambiente local.
"""

import ipaddress
import math
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
        raise GeoError("Adicione a base IP2Location DB11 em data/ip2location/IP2LOCATION-LITE-DB11.BIN.")

    try:
        import IP2Location
        reader = IP2Location.IP2Location(str(DB_FILE))
        try:
            result = reader.get_all(ip)
        finally:
            reader.close()
    except (ImportError, OSError) as exc:
        raise GeoError("Não foi possível abrir o banco IP2Location.") from exc

    def clean(value):
        if (value is None or str(value).strip() in ("", "-")
                or str(value).upper().startswith(("NOT SUPPORTED", "INVALID IP", "THIS PARAMETER IS UNAVAILABLE"))):
            return None
        return value

    def coordinate(value, limit):
        value = clean(value)
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        return number if math.isfinite(number) and abs(number) <= limit else None

    country = clean(result.country_short)
    if not isinstance(country, str) or len(country) != 2 or not country.isascii() or not country.isalpha():
        raise GeoError("O IP2Location não retornou um país válido. Confira a cobertura IPv4/IPv6 da base.")

    return {
        "ip": ip,
        "country": country,
        "region": clean(result.region),
        "city": clean(result.city),
        "latitude": coordinate(result.latitude, 90),
        "longitude": coordinate(result.longitude, 180),
        "asn": clean(getattr(result, "asn", None)),
        "organization": clean(getattr(result, "as_name", None)) or clean(getattr(result, "isp", None)),
        "source": "IP2LOCATION",
    }


def same_location(actual: dict, claimed: dict) -> bool:
    """Compara contexto (sem confiar em coordenadas fornecidas pelo cliente)."""
    return all(actual.get(k) == claimed.get(k)
               for k in ("ip", "country", "region", "city", "source"))
