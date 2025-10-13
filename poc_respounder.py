#!/usr/bin/env python3
"""
PoC respounder — prouve la logique de détection d'un poisoner LLMNR.

Principe : respounder interroge le réseau avec un nom d'hôte qui N'EXISTE PAS.
  - Réseau sain      : personne ne répond            -> RAS
  - Poisoner présent : Responder répond à TOUT        -> [RESPONDER DETECTED]

Ce PoC est autonome (aucun privilège, aucun Docker) : il monte un faux poisoner
en thread sur la loopback et lance la même logique de sonde que `main.go`. Les
paquets LLMNR sont construits à l'identique du code Go (cf. sendLLMNRProbe).
Sur un vrai LAN, la sonde part en multicast vers 224.0.0.252:5355.
"""

import random
import socket
import string
import struct
import sys
import threading

RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
BOLD = "\033[1m"
RESET = "\033[0m"

LLMNR_TYPE_A = 0x0001
LLMNR_CLASS_IN = 0x0001


def build_llmnr_query(name: str, txid: int = 0x0001) -> bytes:
    """Trame LLMNR identique à main.go : header + label unique + type A / classe IN."""
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)  # txid, flags, qd=1, an/ns/ar=0
    qname = bytes([len(name)]) + name.encode()                 # un seul label préfixé par sa longueur
    return header + qname + b"\x00" + struct.pack(">HH", LLMNR_TYPE_A, LLMNR_CLASS_IN)


def build_llmnr_response(query: bytes, poison_ip: str) -> bytes:
    """Réponse empoisonnée : ce que renvoie Responder — un enregistrement A vers SON IP."""
    txid = query[:2]
    flags = struct.pack(">H", 0x8000)                          # QR=1 (réponse)
    counts = struct.pack(">HHHH", 1, 1, 0, 0)                   # qd=1, an=1, ns=0, ar=0
    question = query[12:]                                       # on ré-émet la question telle quelle
    answer = (
        b"\xc0\x0c"                                             # pointeur de compression vers le nom
        + struct.pack(">HH", LLMNR_TYPE_A, LLMNR_CLASS_IN)
        + struct.pack(">I", 30)                                # TTL
        + struct.pack(">H", 4)                                 # RDLENGTH
        + socket.inet_aton(poison_ip)                          # RDATA = IP de l'attaquant
    )
    return txid + flags + counts + question + answer


def parse_poisoned_ip(resp: bytes) -> str | None:
    """Extrait l'IP du dernier enregistrement A (les 4 derniers octets si RDLENGTH=4)."""
    try:
        if len(resp) >= 4 and struct.unpack(">H", resp[-6:-4])[0] == 4:
            return socket.inet_ntoa(resp[-4:])
    except (struct.error, OSError):
        pass
    return None


def random_hostname() -> str:
    prefixes = ["ADMIN", "SRV", "WORKSTATION", "LAPTOP", "PC", "ERP", "DEV"]
    suffix = "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
    return f"{random.choice(prefixes)}-{suffix}"


def start_silent_host() -> int:
    """Hôte sain : reçoit les requêtes LLMNR mais ne répond JAMAIS. Renvoie son port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    def loop():
        while True:
            try:
                sock.recvfrom(2048)  # on draine, on ignore
            except OSError:
                return

    threading.Thread(target=loop, daemon=True).start()
    return port


def start_poisoner(poison_ip: str) -> int:
    """Faux Responder : répond à TOUTE requête avec un A record pointant vers poison_ip."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    def loop():
        while True:
            try:
                data, addr = sock.recvfrom(2048)
            except OSError:
                return
            sock.sendto(build_llmnr_response(data, poison_ip), addr)

    threading.Thread(target=loop, daemon=True).start()
    return port


def probe(target: tuple[str, int], name: str, timeout: float = 2.0):
    """Logique respounder : envoie la sonde, renvoie (responder_ip, poisoned_ip) si réponse."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_llmnr_query(name), target)
        data, addr = sock.recvfrom(2048)        # toute réponse = poisoner (le nom est fictif)
        return addr[0], parse_poisoned_ip(data)
    except socket.timeout:
        return None
    finally:
        sock.close()


def main():
    print()
    print(f"  {BOLD}{'=' * 68}{RESET}")
    print(f"  {BOLD}  PoC respounder — détection d'un poisoner LLMNR{RESET}")
    print(f"  {BOLD}{'=' * 68}{RESET}")

    name = random_hostname()
    query = build_llmnr_query(name)
    print(f"\n  Nom d'hôte fictif interrogé : {CYAN}{name}{RESET}  {YELLOW}(n'existe pas){RESET}")
    print(f"  Trame LLMNR envoyée         : {CYAN}{query.hex()}{RESET}")
    print(f"  {YELLOW}(format identique à sendLLMNRProbe() dans main.go){RESET}")

    exit_code = 0

    # ── Scénario 1 : réseau sain ──────────────────────────────────────────
    print(f"\n  {BOLD}Scénario 1 — réseau sain{RESET} (aucun poisoner)")
    clean_port = start_silent_host()
    res = probe(("127.0.0.1", clean_port), random_hostname())
    if res is None:
        print(f"  Résultat : {GREEN}AUCUN RESPONDER{RESET} — la sonde expire, RAS. ✅")
    else:
        print(f"  Résultat : {RED}réponse inattendue {res}{RESET} ❌")
        exit_code = 1

    # ── Scénario 2 : poisoner actif (type Responder) ──────────────────────
    print(f"\n  {BOLD}Scénario 2 — poisoner actif{RESET} (Responder à l'écoute)")
    poison_ip = "192.168.166.2"
    rogue_port = start_poisoner(poison_ip)
    res = probe(("127.0.0.1", rogue_port), random_hostname())
    if res is not None:
        responder_ip, poisoned_ip = res
        print(f"  Résultat : {RED}[RESPONDER DETECTED]{RESET} — une machine a répondu "
              f"à un nom fictif. 🚨")
        print(f"             Réponse reçue de   : {CYAN}{responder_ip}{RESET}")
        print(f"             IP empoisonnée (A) : {CYAN}{poisoned_ip}{RESET}  "
              f"{YELLOW}(l'attaquant se fait passer pour cette IP){RESET}")
    else:
        print(f"  Résultat : {RED}échec — le poisoner aurait dû répondre{RESET} ❌")
        exit_code = 1

    # ── Conclusion ────────────────────────────────────────────────────────
    print(f"\n  {BOLD}{'=' * 68}{RESET}")
    print(f"  {BOLD}CONCLUSION{RESET}")
    print(f"  {BOLD}{'=' * 68}{RESET}\n")
    print(f"  Interroger un nom d'hôte {BOLD}qui n'existe pas{RESET} est un test décisif :")
    print(f"  sur un réseau sain personne ne répond, alors qu'un poisoner LLMNR")
    print(f"  (Responder) répond à tout pour capturer des authentifications NTLM.")
    print(f"  Toute réponse = {RED}empoisonnement en cours{RESET}.\n")
    print(f"  En conditions réelles, remplacer la cible loopback par le multicast")
    print(f"  {CYAN}224.0.0.252:5355{RESET} (LLMNR) / {CYAN}224.0.0.251:5353{RESET} (mDNS) — "
          f"c.-à-d. lancer {BOLD}respounder{RESET}.\n")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
