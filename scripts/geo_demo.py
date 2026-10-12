"""Demonstra consulta REAL ao banco local IP2Location com um IP público."""

from shared.geo import GeoError, lookup_ip


if __name__ == "__main__":
    ip = input("IP público para consultar (ex.: 8.8.8.8): ").strip()
    try:
        print(lookup_ip(ip))
    except (GeoError, ImportError, OSError) as exc:
        print(f"Não foi possível consultar: {exc}")
