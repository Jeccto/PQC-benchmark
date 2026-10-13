FROM archlinux:latest

# Toolchain + runtime dependencies:
#   base-devel cmake ninja git  -> build liboqs from source
#   python python-pip           -> run the server
#   tk                          -> server.py imports tkinter at module load (GUI when a display exists)
#   iputils tcpdump             -> packet-capture experiments (see ToAdd.md)
RUN pacman -Syu --noconfirm \
    base-devel cmake ninja git python python-pip iputils tcpdump tk

# Build and install liboqs, the C implementation of ML-KEM used through liboqs-python.
RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs /opt/liboqs && \
    cmake -S /opt/liboqs -B /opt/liboqs/build -DBUILD_SHARED_LIBS=ON && \
    cmake --build /opt/liboqs/build --parallel $(nproc) && \
    cmake --install /opt/liboqs/build && \
    ldconfig

ENV LD_LIBRARY_PATH=/usr/local/lib

WORKDIR /app
COPY requirements.txt .
RUN pip install --break-system-packages -r requirements.txt
COPY src/ ./src/

# server.py resolves "server_identity_private.pem" relative to the working directory,
# so run from src/. This container has no display, so server.py automatically takes its
# headless fallback path (the Tkinter GUI is skipped) — no X server / Xvfb is required.
WORKDIR /app/src

EXPOSE 5000

# Generate the Ed25519 identity keypair on first start if none was mounted in, then exec
# the server (-u keeps the headless log lines unbuffered so `docker logs` shows them live).
# Mount your own key for a stable identity across containers:
#   -v "$PWD/server_identity_private.pem:/app/src/server_identity_private.pem"
CMD ["sh", "-c", "[ -f server_identity_private.pem ] || python gen_indentity.py; exec python -u server.py"]
