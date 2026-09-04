
import sys
import struct

VERDE = "\033[92m"
RESET = "\033[0m"

# Frecuencias de letras del espanol (proporciones, suman ~1)
FREQ_ES = {
    'a': 0.1253, 'b': 0.0142, 'c': 0.0468, 'd': 0.0586, 'e': 0.1368,
    'f': 0.0069, 'g': 0.0101, 'h': 0.0070, 'i': 0.0625, 'j': 0.0044,
    'k': 0.0002, 'l': 0.0497, 'm': 0.0315, 'n': 0.0671, 'o': 0.0868,
    'p': 0.0251, 'q': 0.0088, 'r': 0.0687, 's': 0.0798, 't': 0.0463,
    'u': 0.0393, 'v': 0.0090, 'w': 0.0001, 'x': 0.0022, 'y': 0.0090,
    'z': 0.0052,
}

# Frecuencias de letras del ingles (por si el mensaje esta en ingles)
FREQ_EN = {
    'a': 0.0817, 'b': 0.0150, 'c': 0.0278, 'd': 0.0425, 'e': 0.1270,
    'f': 0.0223, 'g': 0.0202, 'h': 0.0609, 'i': 0.0697, 'j': 0.0015,
    'k': 0.0077, 'l': 0.0403, 'm': 0.0241, 'n': 0.0675, 'o': 0.0751,
    'p': 0.0193, 'q': 0.0010, 'r': 0.0599, 's': 0.0633, 't': 0.0906,
    'u': 0.0276, 'v': 0.0098, 'w': 0.0236, 'x': 0.0015, 'y': 0.0197,
    'z': 0.0007,
}


# ----------------------------- Cifrado Cesar -----------------------------

def desplazar(texto, k):
    """Desplaza las letras de 'texto' en k (k negativo = descifrar)."""
    res = []
    k %= 26
    for c in texto:
        if c.isupper():
            res.append(chr((ord(c) - 65 + k) % 26 + 65))
        elif c.islower():
            res.append(chr((ord(c) - 97 + k) % 26 + 97))
        else:
            res.append(c)
    return "".join(res)


def _chi2(texto, freq):
    """Chi-cuadrado de 'texto' vs. una tabla de frecuencias. Menor = mejor calce."""
    letras = [c.lower() for c in texto if c.isalpha() and c.lower() in freq]
    n = len(letras)
    if n == 0:
        return float("inf")
    conteo = {}
    for c in letras:
        conteo[c] = conteo.get(c, 0) + 1
    score = 0.0
    for letra, f in freq.items():
        esperado = f * n
        observado = conteo.get(letra, 0)
        score += (observado - esperado) ** 2 / esperado
    return score


def probabilidad_texto(texto):
    """
    Puntaje de que 'texto' sea lenguaje real. Menor = mas probable.
    Toma el mejor calce entre espanol e ingles, asi funciona con mensajes
    en cualquiera de los dos idiomas.
    """
    return min(_chi2(texto, FREQ_ES), _chi2(texto, FREQ_EN))


# --------------------- Lector de capturas pcapng / pcap ---------------------

def _leer_pcapng(data):
    """Devuelve lista de (linktype, frame_bytes) desde un archivo pcapng."""
    # El byte-order magic (0x1A2B3C4D) esta en el primer SHB, offset 8
    bom = data[8:12]
    if bom == b"\x4d\x3c\x2b\x1a":
        e = "<"
    elif bom == b"\x1a\x2b\x3c\x4d":
        e = ">"
    else:
        raise ValueError("pcapng: byte-order magic no reconocido")

    frames = []
    linktypes = {}
    iface_idx = 0
    off = 0
    n = len(data)
    while off + 12 <= n:
        btype = struct.unpack_from(e + "I", data, off)[0]
        blen = struct.unpack_from(e + "I", data, off + 4)[0]
        if blen < 12 or off + blen > n:
            break
        body = data[off + 8: off + blen - 4]

        if btype == 0x00000001:                 # Interface Description Block
            lt = struct.unpack_from(e + "H", body, 0)[0]
            linktypes[iface_idx] = lt
            iface_idx += 1
        elif btype == 0x00000006:               # Enhanced Packet Block
            iface_id = struct.unpack_from(e + "I", body, 0)[0]
            caplen = struct.unpack_from(e + "I", body, 12)[0]
            pkt = body[20:20 + caplen]
            frames.append((linktypes.get(iface_id, 1), pkt))
        elif btype == 0x00000003:               # Simple Packet Block
            origlen = struct.unpack_from(e + "I", body, 0)[0]
            pkt = body[4:4 + origlen]
            frames.append((linktypes.get(0, 1), pkt))
        elif btype == 0x00000002:               # Packet Block (obsoleto)
            caplen = struct.unpack_from(e + "I", body, 4)[0]
            pkt = body[8:8 + caplen]
            frames.append((linktypes.get(0, 1), pkt))

        off += blen
    return frames


def _leer_pcap(data):
    """Devuelve lista de (linktype, frame_bytes) desde un archivo pcap clasico."""
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    else:
        raise ValueError("pcap: magic no reconocido")

    linktype = struct.unpack_from(e + "I", data, 20)[0]
    frames = []
    off = 24
    n = len(data)
    while off + 16 <= n:
        incl_len = struct.unpack_from(e + "I", data, off + 8)[0]
        pkt = data[off + 16: off + 16 + incl_len]
        frames.append((linktype, pkt))
        off += 16 + incl_len
    return frames


def leer_captura(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return _leer_pcapng(data)
    return _leer_pcap(data)


# --------------------- Ubicar el IP dentro de cada frame ---------------------

def offset_ip(linktype, frame):
    """Devuelve el offset donde empieza la cabecera IPv4, o None."""
    if linktype == 1:                    # Ethernet
        if len(frame) < 14:
            return None
        eth = struct.unpack_from(">H", frame, 12)[0]
        if eth == 0x0800:
            return 14
        if eth == 0x8100 and len(frame) >= 18:   # VLAN 802.1Q
            if struct.unpack_from(">H", frame, 16)[0] == 0x0800:
                return 18
        return None
    if linktype == 0:                    # BSD loopback (Null) -> familia 4 bytes
        if len(frame) < 4:
            return None
        fam_le = struct.unpack_from("<I", frame, 0)[0]
        fam_be = struct.unpack_from(">I", frame, 0)[0]
        return 4 if 2 in (fam_le, fam_be) else None
    if linktype == 101:                  # RAW IP
        return 0
    if linktype == 113:                  # Linux cooked (SLL)
        return 16
    if linktype == 276:                  # Linux cooked v2 (SLL2)
        return 20
    return None


def extraer_mensaje(frames):
    """Reconstruye el texto cifrado desde el ultimo byte de cada echo request."""
    msg = []
    for linktype, frame in frames:
        ipoff = offset_ip(linktype, frame)
        if ipoff is None or ipoff + 20 > len(frame):
            continue
        if (frame[ipoff] >> 4) != 4:                 # IPv4?
            continue
        ihl = (frame[ipoff] & 0x0f) * 4
        if frame[ipoff + 9] != 1:                    # protocolo ICMP?
            continue
        icmp_off = ipoff + ihl
        if icmp_off + 8 > len(frame):
            continue
        if frame[icmp_off] != 8:                     # solo Echo Request (type 8)
            continue
        total_len = struct.unpack_from(">H", frame, ipoff + 2)[0]
        ip_end = ipoff + total_len
        if ip_end > len(frame) or ip_end <= icmp_off + 8:
            ip_end = len(frame)                      # sin padding: fin del frame
        msg.append(chr(frame[ip_end - 1]))
    return "".join(msg)


# --------------------------------- Main ---------------------------------

def main():
    if len(sys.argv) != 2:
        print("Uso: sudo python3 readv2.py <archivo.pcapng|.pcap>")
        sys.exit(1)

    path = sys.argv[1]
    try:
        frames = leer_captura(path)
    except (OSError, ValueError) as ex:
        print(f"[!] No se pudo leer la captura: {ex}")
        sys.exit(1)

    cifrado = extraer_mensaje(frames)
    if not cifrado:
        print("[!] No se encontraron paquetes ICMP Echo Request con datos.")
        sys.exit(1)

    print(f"[*] Archivo                 : {path}")
    print(f"[*] Caracteres recuperados  : {len(cifrado)}")
    print(f"[*] Texto cifrado recuperado: {cifrado!r}\n")

    # Probar los 26 corrimientos y elegir el mas probable
    candidatos = []
    for k in range(26):
        plano = desplazar(cifrado, -k)          # descifrar = desplazar hacia atras
        candidatos.append((k, plano, probabilidad_texto(plano)))

    mejor_k = min(candidatos, key=lambda x: x[2])[0]

    print("Todas las combinaciones posibles (corrimiento -> texto):")
    for k, plano, _ in candidatos:
        linea = f"  k={k:>2} : {plano}"
        if k == mejor_k:
            print(f"{VERDE}{linea}   <-- mas probable{RESET}")
        else:
            print(linea)

    print(f"\n[*] Mensaje en claro mas probable (corrimiento {mejor_k}): "
          f"{VERDE}{desplazar(cifrado, -mejor_k)}{RESET}")


if __name__ == "__main__":
    main()
