
import os
import sys
import time
import socket
import struct
import platform

DEFAULT_DEST = "8.8.8.8"     # destino por defecto (se ve como un ping normal a afuera)
ICMP_ECHO_REQUEST = 8
DATALEN = 56                 # bytes de data del ping por defecto
INTERVALO = 1.0              # segundos entre paquetes (igual que 'ping' por defecto)


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return (~total) & 0xffff


def detectar_so():
    """Devuelve 'macos' o 'linux' segun el sistema donde corre el programa."""
    return "macos" if platform.system() == "Darwin" else "linux"


def build_ping_payload(so):
    """
    Construye los 56 bytes de data identicos a los que genera 'ping' por
    defecto en el SO indicado. Devuelve un bytearray.
    """
    payload = bytearray(DATALEN)

    # Tamano del timestamp segun el SO (struct timeval)
    ts_len = 8 if so == "macos" else 16

    # Timestamp real en los primeros bytes (varia en cada paquete, como el ping real)
    ahora = time.time()
    seg = int(ahora)
    usec = int((ahora - seg) * 1_000_000)
    if so == "macos":
        # BSD struct tv32: int32 sec + int32 usec  (8 bytes)
        struct.pack_into("<II", payload, 0, seg & 0xffffffff, usec & 0xffffffff)
    else:
        # Linux struct timeval 64-bit: long sec + long usec  (16 bytes)
        struct.pack_into("<q", payload, 0, seg)
        struct.pack_into("<q", payload, 8, usec)

    # Patron de relleno: cada byte = su indice (0x10..0x37 en Linux, 0x08..0x37 en macOS)
    for i in range(ts_len, DATALEN):
        payload[i] = i & 0xff

    return payload


def build_icmp_packet(identifier, seq, payload):
    """Arma un ICMP Echo Request completo, con checksum correcto."""
    # 1) cabecera con checksum en 0 para poder calcularlo
    cabecera = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, identifier, seq)
    chk = checksum(cabecera + bytes(payload))
    # 2) cabecera final con el checksum ya calculado
    cabecera = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chk, identifier, seq)
    return cabecera + bytes(payload)


def hexdump(data):
    """Representacion hex simple del campo data, para comparar en el informe."""
    return " ".join(f"{b:02x}" for b in data)


def main():
    if len(sys.argv) < 2:
        print('Uso: sudo python3 pingv4.py "mensaje_cifrado" [destino]')
        sys.exit(1)

    mensaje = sys.argv[1]
    destino = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_DEST
    so = detectar_so()

    print(f"[*] SO detectado : {so}  (replicando el payload de ping de {so})")
    print(f"[*] Destino      : {destino}")
    print(f"[*] Mensaje      : {mensaje!r}  ({len(mensaje)} caracteres)")

    # Socket raw ICMP (requiere privilegios de root -> sudo)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("[!] Se requieren privilegios de root. Ejecuta: sudo python3 pingv4.py ...")
        sys.exit(1)

    identifier = os.getpid() & 0xffff
    dest_ip = socket.gethostbyname(destino)

    for i, ch in enumerate(mensaje):
        seq = i + 1
        payload = build_ping_payload(so)
        payload[-1] = ord(ch) & 0xff          # caracter secreto en el ultimo byte
        paquete = build_icmp_packet(identifier, seq, payload)

        try:
            sock.sendto(paquete, (dest_ip, 0))
        except OSError as e:
            # Si el destino no es alcanzable, no abortamos: seguimos con el resto
            print(f"    seq={seq:>2}  char={ch!r:>4}  [!] no se pudo enviar ({e})")
            time.sleep(INTERVALO)
            continue

        print(f"    seq={seq:>2}  char={ch!r:>4}  ultimo_byte=0x{payload[-1]:02x}")
        if seq == 1:
            print(f"        data[seq=1] = {hexdump(payload)}")
        time.sleep(INTERVALO)

    sock.close()
    print(f"[*] Listo: {len(mensaje)} paquetes ICMP enviados a {destino}.")


if __name__ == "__main__":
    main()
