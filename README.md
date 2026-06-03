# STP Claim Root Attack — Root Bridge Hijack

Autor: Junior Javier Santos Perez

Matrícula: 2024-1599

Herramienta: stp_root_claim.py

Plataforma de laboratorio: GNS3 + Kali Linux 2025.3

Link video: https://www.youtube.com/watch?v=Mv7JZszYmu4&t=2s 

Enlace GitHub: https://github.com/juniorjaviersantosperez/STP-Claim-Root-Attack 


---

## Descripción

Script de ataque **STP Root Claim** implementado en Python con raw sockets. Envía BPDUs de configuración con prioridad `0` hacia los switches de la red, forzándolos a ceder la posición de Root Bridge al atacante. Una vez que el atacante se convierte en Root Bridge, todo el tráfico L2 de la red pasa por él (Man in the Middle).

---

## 🖧 Topología de Red

> Topología implementada en **GNS3** — Red `10.0.99.0/24`

**IMAGEN 1**

| Nodo | Rol | IP | Interfaz |
|------|-----|----|----------|
| kali-linux-2025.3 | Atacante | 10.0.99.100 | eth0 |
| Clonekali-1 | Víctima | 10.0.99.50 | e0 |
| Swich-1 | Switch Root (antes del ataque) | N/A | e0, e1, e2 |
| Swich-2 | Switch intermedio | N/A | e0, e1, e2 |
| Swich-3 | Switch intermedio | N/A | e0, e1, e2 |
| R1 | Router / Gateway | 10.0.99.1 | f0/0 |

**Red:** `10.0.99.0/24` | **Máscara:** `255.255.255.0` | **Gateway:** `10.0.99.1`

---

## ⚙️ Requisitos

```bash
# Python 3
python3 --version

# Solo librerías estándar — sin dependencias externas
# socket, struct, os, signal (incluidas en Python 3)
```

---

## 📄 Código del Script

El script construye BPDUs STP en **raw bytes** directamente sobre un socket `AF_PACKET`, garantizando compatibilidad con switches Cisco IOS. Envía dos tipos de BPDUs:

- **Configuration BPDU** → anuncia al atacante como Root Bridge con prioridad `0`
- **TCN BPDU** (`--tcn`) → fuerza reconvergencia continua en todos los switches

**MAC del atacante verificada:**

**IMAGEN 5**

---

## 🚀 Uso

```bash
# Básico
sudo python3 stp_root_claim.py

# Con TCN — fuerza reconvergencia continua (más agresivo)
sudo python3 stp_root_claim.py -i eth0 -p 0 -t 1 --tcn

# Intervalo rápido
sudo python3 stp_root_claim.py -i eth0 -p 0 -t 0.5
```

### Parámetros

| Flag | Descripción | Default |
|------|-------------|---------|
| `-i` | Interfaz de red | `eth0` |
| `-p` | Bridge priority (0 = mínima) | `0` |
| `-t` | Intervalo entre BPDUs en segundos | `2` |
| `--tcn` | Enviar TCN BPDUs (reconvergencia) | `Off` |

---

## ▶️ Ejecución del Ataque

El script envía **526 BPDUs** en 263 segundos anunciando al atacante como Root Bridge con prioridad `0` y MAC `00:0c:29:b0:f6:1c`:

**IMAGEN 2**

---

## ✅ Verificación del Ataque

### Método 1 — Ver BPDUs saliendo en tiempo real

```bash
sudo tcpdump -i eth0 -e -nn ether dst 01:80:c2:00:00:00
```

Se observan los BPDUs Configuration y TCN saliendo continuamente desde la MAC del atacante hacia la dirección multicast STP `01:80:c2:00:00:00`:

**IMAGEN 3**

---

### Método 2 — show spanning-tree en los switches (antes del ataque)

**Swich-1 antes del ataque** — Root Bridge legítimo con prioridad `32769`:

**IMAGEN 7**

**Swich-3 antes del ataque** — Root Bridge legítimo con prioridad `32769`:

**IMAGEN 6**

---

### Método 3 — show spanning-tree en Swich-2 (prueba definitiva)

**ANTES** del ataque — Swich-2 es el Root Bridge con prioridad `32769`.

**DESPUÉS** del ataque — Root ID cambia a prioridad `0` y dirección `000c.29b0.f61c` (MAC del atacante):

**IMAGEN 4**

```
Root ID   Priority   0
          Address    000c.29b0.f61c  ← MAC del atacante ✅
          Cost       4
          Port       1 (GigabitEthernet0/0)
```

> ✅ **El atacante se convierte en Root Bridge — Ataque exitoso**

---

## 🛡️ Contramedidas

### BPDU Guard — Protección por puerto

BPDU Guard deshabilita automáticamente el puerto si recibe un BPDU no autorizado, bloqueando el ataque inmediatamente:

**IMAGEN 8**

```
Switch(config)# interface GigabitEthernet0/0
Switch(config-if)# description ATAQUE
Switch(config-if)# switchport mode access
Switch(config-if)# spanning-tree portfast
Switch(config-if)# spanning-tree bpduguard enable
Switch(config-if)# end
Switch# wr
```

### Root Guard

```
Switch(config-if)# spanning-tree guard root
```

### Otras contramedidas

| Contramedida | Efectividad | Descripción |
|---|---|---|
| BPDU Guard | Muy Alta | Apaga el puerto si recibe BPDUs no autorizados |
| Root Guard | Alta | Impide que un puerto se convierta en Root Port |
| Port Security | Alta | Limita MACs por puerto |
| BPDU Filter | Media | Filtra BPDUs entrantes y salientes |

---


## ⚠️ Disclaimer

Este script fue desarrollado **exclusivamente con fines educativos** en un entorno de laboratorio controlado (GNS3). El uso de esta herramienta contra redes sin autorización expresa es **ilegal**. El autor no se hace responsable del mal uso de este código.
