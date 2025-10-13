# Attacker box — runs SpiderLabs Responder (the LLMNR/NBT-NS/mDNS poisoner)
# https://github.com/lgandx/Responder
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git python3 python3-pip python3-netifaces iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/lgandx/Responder /opt/Responder
WORKDIR /opt/Responder
# Responder needs aioquic (+ whatever else its requirements list).
RUN pip install --break-system-packages --no-cache-dir aioquic || \
    pip install --break-system-packages --no-cache-dir -r requirements.txt || true

# Poisoning mode ON (default): Responder answers every LLMNR/mDNS/NBNS query.
CMD ["python3", "Responder.py", "-I", "eth0"]
