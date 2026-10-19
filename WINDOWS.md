# Running the project on Windows (Docker Desktop)

This guide covers the **Windows workflow**: the server runs in a Linux container under
Docker Desktop, and the client runs either natively on Windows (GUI) or on another machine.
For the protocol itself, see `README.md`; for a full code briefing, see `report/CODEBASE_REPORT.md`.

> **Scope**: Docker Desktop with the **WSL2 backend** on Windows 10/11 x64.
> Windows *containers* (`mcr.microsoft.com/windows/servercore`) are **not** supported —
> `Dockerfile.windows` builds a Linux image, which is what Docker Desktop runs by default.

---

## 1. Prerequisites

| Thing | Notes |
|---|---|
| Docker Desktop | Latest version, WSL2 backend. Open it once so the engine is running. |
| Linux engine mode | Whale icon in the tray must show you are on **Linux** containers (it offers "Switch to Windows containers…" when you already are — do **not** press it). |
| PowerShell | Any recent PowerShell; commands below are copy-paste ready. |
| (Client, native only) Python 3.10+ | Install from [python.org](https://python.org/downloads) — the **official installer includes tkinter**, which `client.py` needs. Microsoft Store Python is a common source of tkinter problems. |
| (Client, native only) Git + CMake + VS Build Tools | Only needed for `liboqs`; see §5. |

---

## 2. Get the code

The project is the **inner** folder `pq-hybrid-kem/` (it has its own `.git`). All commands
below assume you are inside it:

```powershell
cd path\to\PQC-benchmark\PQC-benchmark\pq-hybrid-kem
```

Line endings matter: a Dockerfile checked out with CRLF breaks `docker build`
(`unknown instruction` / `/bin/sh: not found`). The included `.gitattributes` forces LF for
Dockerfiles and shell scripts; if you copied the files by hand and the build complains, run
`dos2unix Dockerfile.windows` or re-checkout with `git config core.autocrlf input`.

---

## 3. Build and run the server

**Option A — Compose (recommended):**

```powershell
docker compose up --build        # first build compiles liboqs: several minutes
docker compose up --build -d     # detached; follow logs with: docker compose logs -f
docker compose down
```

**Option B — plain docker (mirrors README.md §9):**

```powershell
docker build -f Dockerfile.windows -t pq-hybrid-kem .
docker run -it --rm -p 5000:5000 --name server pq-hybrid-kem
```

Expected headless output:

```
No display found — starting headless server on 0.0.0.0:5000
Server listening on 0.0.0.0:5000
```

### Why `-p 5000:5000` and not the README's `--network pq-net --ip 192.168.56.10`?

The README's static-IP setup assumes a Linux/VirtualBox-style network where a container IP
is directly reachable. On Docker Desktop the container subnet lives **inside the WSL2 VM**
and is not routable from Windows or your LAN — use **port publishing** instead. The client
then simply connects to `localhost:5000` (or to the machine's LAN IP from elsewhere, see §5).

**Important**: the server accepts **exactly one** connection and then exits. Don't probe
port 5000 with `Test-NetConnection` — that consumes the single slot and kills the server.

---

## 4. Identity keys

On first start the container generates an Ed25519 identity keypair inside itself
(`gen_indentity.py` runs automatically when no private key was mounted). The client needs
the matching **public** key, so copy it out:

```powershell
docker cp server:/app/src/server_identity_public.pem .\src\server_identity_public.pem
```

Every **fresh** container run generates a *new* keypair (with `--rm` that is every `docker
run`), so you must re-copy the public key each time. For a stable identity, generate the
keypair once on the host and mount it:

```powershell
# one-off container that writes the keypair into your host .\src folder:
docker run --rm -v "${PWD}\src:/app/src" pq-hybrid-kem python gen_indentity.py
# then either mount it manually:
docker run -it --rm -p 5000:5000 --name server `
  -v "${PWD}\src\server_identity_private.pem:/app/src/server_identity_private.pem" `
  pq-hybrid-kem
# ...or uncomment the volumes: section in docker-compose.yml (make the path match).
```

> If the host-side path does not exist, Docker silently creates an **empty directory** in
> its place and the server fails with `Could not deserialize key data`. Always create the
> file first (`New-Item .\src\server_identity_private.pem` is not enough — it must contain
> the PEM, i.e. come from `gen_indentity.py`).

The private key never leaves the server side; only the `.pem` public key travels to the client.

---

## 5. Run the client

### Option A — native Windows client (GUI, connects to `localhost`)

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

cd src                      # client.py reads server_identity_public.pem relative to cwd
python client.py            # enter 127.0.0.1, a message, a tamper mode -> Send
```

`cryptography` ships prebuilt Windows wheels, so the only native dependency left is
**liboqs** (the C ML-KEM implementation). `liboqs-python` handles it automatically: the
first `import oqs` downloads and builds liboqs 0.16.0 for you — but building requires:

* [Git](https://git-scm.com/download/win),
* [CMake](https://cmake.org/download/),
* [Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/) with the
  **Desktop development with C++** workload (MSVC + Windows SDK).

Alternatives if you don't want the automatic build:

* **Manual build** — build liboqs with the mandatory flag and put the DLL on `PATH`
  (or set `OQS_INSTALL_PATH`):

  ```powershell
  git clone --depth=1 https://github.com/open-quantum-safe/liboqs
  cmake -S liboqs -B liboqs\build -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=C:\liboqs
  cmake --build liboqs\build --config Release --parallel 8
  cmake --install liboqs\build
  # then, in every new shell before running the client:
  $env:Path += ";C:\liboqs\bin"        # oqs.dll lives here
  ```
* **Prebuilt DLLs** — third-party (unofficial) binaries exist, e.g.
  `bardiakz/liboqs-binaries` releases (`liboqs-*-windows-x64.zip`, extract `lib\oqs.dll`
  onto your `PATH`). Use at your own risk; building from source is the recommended route.

### Option B — client on another machine (easiest if you don't want liboqs on Windows)

The client needs no changes to reach a Windows-hosted server — find the Windows machine's
LAN IP (`ipconfig` → "IPv4 Address"), allow the port inbound **as Administrator**:

```powershell
New-NetFirewallRule -DisplayName "pq-hybrid-kem 5000" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow
```

then run `python src/client.py` on the other machine (e.g. your Linux box) and enter that
IP. The Windows machine never needs Python or liboqs in this setup — only Docker.

---

## 6. Verify the demos

With the server running (§3) and the client connected to the right address:

| Tamper target | Expected client log | Expected server log |
|---|---|---|
| `None` | `Server replied: server received N bytes` | `Message 1 from client: …` |
| `Ciphertext` | `No valid acknowledgement from the server` | `REJECTED record … failed authentication` |
| `Replay` | `No valid acknowledgement from the server` | `REJECTED record … failed authentication` |

The over-the-wire benchmark (`src/Benchmark/`) also works, but note **port 5000 is exclusive**:
stop the server container first, and remember the benchmark pair speaks an older protocol
variant than `server.py`/`client.py` (see `report/CODEBASE_REPORT.md` §7.2).

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `unknown instruction: …` or `$'\r': command not found` during build | CRLF line endings. Re-checkout with the repo's `.gitattributes`, or `dos2unix Dockerfile.windows`. |
| `image operating system "linux" cannot be used on this platform` | Docker Desktop is in **Windows containers** mode. Whale icon → *Switch to Linux containers*. |
| `Could not deserialize key data` at server start | The mounted private key path didn't exist, so Docker created a directory there (§4). Delete the directory, create the file, retry. |
| Server dies right after I ran a connection test | The server accepts one connection per run — the test consumed it. Restart it. |
| Client: `Connection refused` from `localhost` | Server not running, port not published (`-p 5000:5000`), or client pointing at the wrong IP. |
| Client: `AUTHENTICATION FAILED: server signature invalid` | The client has a stale `server_identity_public.pem` from an older container. Re-copy it (§4) or mount a stable key. |
| Native client: `TclError: no display name and no $DISPLAY` | You launched it over SSH/headless, or Store Python without tkinter. Use the python.org build. |
| First `import oqs` hangs for minutes | liboqs is being downloaded and compiled automatically (§5). One-time cost. |
| First `docker build` is very slow | Normal: it compiles liboqs from source inside the image. Layer caching makes later builds fast. |
| `docker compose` not found | Use `docker-compose` (hyphenated) for Compose v1, or update Docker Desktop (Compose v2 is bundled). |
