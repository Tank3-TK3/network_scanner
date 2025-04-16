#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import ipaddress
from typing import List

# Importaciones del paquete local
from network_scanner.scanner import perform_scan
from network_scanner.models import DeviceInfo
from network_scanner.utils import Spinner # Importar el Spinner

# Importar constantes si las defines en config.py o mantenerlas aquí
DEFAULT_LOCAL_RANGE = "192.168.1.0/24"
DEFAULT_REMOTE_RANGE = None # No escanear remoto por defecto
DEFAULT_NMAP_ARGS = "-T4 -A"

def print_summary(devices: List[DeviceInfo]) -> None:
    """Imprime el resumen formateado."""
    # Lógica de impresión similar a la anterior, usando DeviceInfo
    print("\n=============================================")
    print("     RESUMEN COMPLETO DE DISPOSITIVOS       ")
    print("=============================================")
    if not devices:
        print("No se encontraron dispositivos o ocurrieron errores.")
        return

    for i, dev in enumerate(devices):
        print(f"--- Dispositivo {i+1} ---")
        print(f"  IP Address : {dev.get('ip', 'N/A')}")
        print(f"  MAC Address: {dev.get('mac', 'N/A')}")
        print(f"  Fabricante : {dev.get('vendor', 'N/A')}")
        print(f"  Hostname   : {dev.get('hostname', 'N/A')}")
        print(f"  Sistema Op.: {dev.get('os', 'N/A')}")
        print(f"  Estado     : {dev.get('status', 'N/A')}")
        print(f"  Origen     : {dev.get('source', 'N/A')}")
        print(f"  Puertos    : {dev.get('ports', 'N/A')}")
        print("-" * 20)

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Escanea redes locales y remotas usando ARP y Nmap.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    # --- Definición de Argumentos ---
    parser.add_argument(
        "--local", metavar="CIDR", type=str, default=DEFAULT_LOCAL_RANGE,
        help="Rango de red local a escanear con ARP+Nmap."
    )
    parser.add_argument(
        "--remote", metavar="CIDR", type=str, default=DEFAULT_REMOTE_RANGE,
        help="Rango de red adicional a escanear solo con Nmap."
    )
    parser.add_argument(
        "--nmap-args", type=str, default=DEFAULT_NMAP_ARGS,
        help="Argumentos para Nmap."
    )
    parser.add_argument(
        "--skip-local", action="store_true", help="Omitir escaneo local."
    )
    parser.add_argument(
        "--skip-remote", action="store_true", help="Omitir escaneo remoto."
    )
    # Añadir aquí argumento para output file si se desea

    args = parser.parse_args()

    # --- Validación y Preparación ---
    local_range_to_scan = args.local if not args.skip_local else None
    remote_range_to_scan = args.remote if not args.skip_remote else None

    if not local_range_to_scan and not remote_range_to_scan:
        print("[!] No hay rangos especificados para escanear. Usa --local o --remote.", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    # Validar rangos con ipaddress
    try:
        if local_range_to_scan:
            ipaddress.ip_network(local_range_to_scan, strict=False)
        if remote_range_to_scan:
            ipaddress.ip_network(remote_range_to_scan, strict=False)
    except ValueError as e:
        print(f"[!] Error: Rango de red inválido: {e}", file=sys.stderr)
        sys.exit(1)

    # --- Ejecución del Escaneo (con Spinner) ---
    print("=============================================")
    print("          INICIO DE ESCANEO DE RED           ")
    print("=============================================")
    all_devices: List[DeviceInfo] = []
    critical_error = False

    # Usar el Spinner como context manager para las operaciones largas
    try:
        # El spinner aquí cubriría toda la llamada a perform_scan
        # O podrías mover el `with Spinner(...)` dentro de perform_scan
        # para cubrir solo las partes de Nmap que son las más lentas.
        # Vamos a dejarlo aquí para simplicidad inicial.
        with Spinner("Realizando escaneos..."):
             all_devices = perform_scan(
                 local_range=local_range_to_scan,
                 remote_range=remote_range_to_scan,
                 nmap_args=args.nmap_args
             )
    except PermissionError:
         # perform_scan ya debería haber impreso el mensaje específico
         critical_error = True
    except Exception as e:
        # Captura errores inesperados que puedan subir hasta aquí
        print(f"\n[!] Error general inesperado: {e}", file=sys.stderr)
        critical_error = True


    # --- Resultados ---
    print_summary(all_devices)

    print("\n[*] Proceso Finalizado.")
    if critical_error:
         print("[!] El proceso finalizó, pero ocurrieron errores críticos.", file=sys.stderr)
         sys.exit(1)

if __name__ == "__main__":
    # (Verificación de permisos como antes, opcional)
    # ...
    main()