FROM archlinux:latest

RUN pacman -Syu --noconfirm \
    base-devel cmake ninja git python python-pip openssl iputils

RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs /opt/liboqs && \
    cmake -S /opt/liboqs -B /opt/liboqs/build -DBUILD_SHARED_LIBS=ON && \
    cmake --build /opt/liboqs/build --parallel $(nproc) && \
    cmake --install /opt/liboqs/build && \
    ldconfig

WORKDIR /app
COPY src/ ./src/
COPY requirements.txt .

RUN pip install --break-system-packages -r requirements.txt

EXPOSE 5000
