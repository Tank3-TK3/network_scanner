# network_scanner/scanner.py
import time
import logging
from typing import List, Dict, Any, Optional, Tuple

# Importaciones locales y de terceros
import nmap
from scapy.all import ARP, Ether, srp
from .models import DeviceInfo
from .utils import get_mac_vendor # Import relativo dentro del paquete

# (Configuración logging Scapy como antes)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# ...etc

DEFAULT_ARP_TIMEOUT = 1

def _parse_nmap_host_data(nm: nmap.PortScanner, ip: str, source: str, arp_mac: Optional[str] = None) -> DeviceInfo:
    """Procesa los datos de Nmap para un host específico."""
    # Lógica de parseo similar a la anterior, pero ahora devuelve un DeviceInfo
    # ... (adaptar la lógica existente) ...
    device_info: DeviceInfo = {
        "ip": ip, "mac": None, "vendor": None, "hostname": None,
        "os": None, "status": "down", "source": source, "ports": None
    }
    # ... rellenar device_info con datos de nm[ip] ...
    # Si se proporcionó una MAC de ARP y Nmap no encontró una, usar la de ARP
    if arp_mac and not device_info.get("mac"):
         device_info["mac"] = arp_mac
         device_info["vendor"] = get_mac_vendor(arp_mac)

    # Rellenar N/A donde falte información si se prefiere
    for key, value in device_info.items():
        if value is None and key != "mac" and key != "vendor": # MAC/Vendor pueden ser None legítimamente
             device_info[key] = "N/A" # type: ignore

    return device_info


def _discover_arp_hosts(network_range: str) -> Dict[str, str]:
    """Usa ARP para descubrir hosts y devuelve un mapeo IP -> MAC."""
    print(f"[*] Realizando descubrimiento ARP en {network_range}...")
    hosts: Dict[str, str] = {}
    try:
        arp_request = ARP(pdst=network_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(broadcast / arp_request, timeout=DEFAULT_ARP_TIMEOUT, verbose=False)
        for _, received in answered:
            hosts[received.psrc] = received.hwsrc
        print(f"[+] {len(hosts)} hosts encontrados vía ARP.")
        return hosts
    except PermissionError:
         print("[!] Error de permisos para ARP. Ejecuta como admin/root.", file=sys.stderr)
         raise # Re-lanzar para que main.py lo maneje
    except Exception as e:
        print(f"[!] Error durante ARP: {e}", file=sys.stderr)
        return {} # Devolver vacío en otros errores ARP

def _run_nmap_scan(targets: List[str], nmap_args: str) -> Optional[nmap.PortScanner]:
    """Ejecuta Nmap sobre una lista de objetivos."""
    if not targets:
        return None
    print(f"[*] Ejecutando Nmap ({nmap_args}) sobre {len(targets)} objetivo(s)...")
    nm = nmap.PortScanner()
    start_time = time.time()
    try:
        # La clase Spinner se usaría en main.py o aquí si la función es larga
        nm.scan(hosts=' '.join(targets), arguments=nmap_args)
        end_time = time.time()
        print(f"[*] Escaneo Nmap completado en {end_time - start_time:.2f} segundos.")
        return nm
    except nmap.PortScannerError as e:
        print(f"\n[!] Error de Nmap: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"\n[!] Error inesperado ejecutando Nmap: {e}", file=sys.stderr)
        return None


def perform_scan(local_range: Optional[str] = None,
                 remote_range: Optional[str] = None,
                 nmap_args: str = "-T4 -A") -> List[DeviceInfo]:
    """
    Orquesta los escaneos ARP y Nmap según los rangos proporcionados.

    Args:
        local_range: Rango local para ARP + Nmap.
        remote_range: Rango remoto/adicional para Nmap solamente.
        nmap_args: Argumentos para Nmap.

    Returns:
        Lista de dispositivos encontrados.
    """
    all_devices: Dict[str, DeviceInfo] = {} # Usar dict para evitar duplicados por IP

    # 1. Escaneo Local (ARP + Nmap)
    if local_range:
        try:
            arp_hosts = _discover_arp_hosts(local_range)
            if arp_hosts:
                nm_local_results = _run_nmap_scan(list(arp_hosts.keys()), nmap_args)
                if nm_local_results:
                    for ip in nm_local_results.all_hosts():
                        arp_mac = arp_hosts.get(ip) # Obtener MAC de ARP para este IP
                        device_info = _parse_nmap_host_data(nm_local_results, ip, "ARP+Nmap", arp_mac)
                        if device_info['status'] == 'up':
                            all_devices[ip] = device_info
                # Añadir hosts que solo respondieron a ARP (si Nmap no los vio 'up')
                for ip, mac in arp_hosts.items():
                     if ip not in all_devices:
                          all_devices[ip] = {
                               "ip": ip, "mac": mac, "vendor": get_mac_vendor(mac),
                               "status": "up (ARP only)", "source": "ARP",
                               "hostname": "N/A", "os": "N/A", "ports": "N/A"
                          } # type: ignore
        except PermissionError:
             # Ya se imprimió el error, main.py podría querer salir
             print("[!] Abortando escaneo local debido a error de permisos.", file=sys.stderr)
             # Podrías decidir si continuar con el remoto o no
        except Exception as e:
             print(f"[!] Error inesperado en escaneo local: {e}", file=sys.stderr)


    # 2. Escaneo Remoto (Solo Nmap)
    if remote_range:
        print("\n---------------------------------------------")
        # Pasar el rango completo a Nmap
        nm_remote_results = _run_nmap_scan([remote_range], nmap_args)
        if nm_remote_results:
            for ip in nm_remote_results.all_hosts():
                 # No hay MAC de ARP aquí
                 device_info = _parse_nmap_host_data(nm_remote_results, ip, "Nmap Remoto")
                 if device_info['status'] == 'up':
                      # Solo añadir si no se encontró ya en el escaneo local
                      if ip not in all_devices:
                           all_devices[ip] = device_info
                      else:
                           # Podrías decidir actualizar info si el remoto es más completo?
                           # Por ahora, priorizamos el local si ya existe.
                           pass


    return list(all_devices.values())