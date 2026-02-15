FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Base tools (fix Ubuntu package names + avoid non-existent packages)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates curl wget git \
    gcc g++ make libc6-dev \
    python3 python3-pip python3-dev \
    gdb gdb-multiarch gdbserver \
    vim nano \
    file strace ltrace binutils patchelf \
    netcat-openbsd socat \
    xxd \
    && rm -rf /var/lib/apt/lists/*

# Install ttyd reliably (Ubuntu repo often missing/old)
ARG TTYD_VERSION=1.7.7
RUN curl -fsSL -o /usr/local/bin/ttyd \
      "https://github.com/tsl0922/ttyd/releases/download/${TTYD_VERSION}/ttyd.x86_64" \
 && chmod 755 /usr/local/bin/ttyd

# Python exploitation tools
RUN pip3 install --no-cache-dir \
    pwntools ropper capstone keystone-engine unicorn pycryptodome

# Optional: pwndbg (can be slow/flaky; kept but won't fail build)
RUN git clone --depth 1 https://github.com/pwndbg/pwndbg /opt/pwndbg && \
    (cd /opt/pwndbg && ./setup.sh) || true

# Create hacker user (uid 1000)
RUN useradd -m -u 1000 -s /bin/bash hacker

# Nice prompt for hacker
RUN echo 'export PS1="\[\033[01;32m\]hacker@workspace\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "' >> /home/hacker/.bashrc && \
    echo 'alias ls="ls --color=auto"' >> /home/hacker/.bashrc && \
    echo 'alias ll="ls -lah"' >> /home/hacker/.bashrc && \
    chown hacker:hacker /home/hacker/.bashrc

# Challenge directory
RUN mkdir -p /challenge && chown root:root /challenge && chmod 755 /challenge

# Copy challenge source and compile
COPY challenge.c /challenge/challenge.c
RUN gcc -O0 -o /challenge/challenge /challenge/challenge.c \
    -fno-stack-protector -z execstack -no-pie -Wno-deprecated-declarations && \
    strip /challenge/challenge || true && \
    chown root:root /challenge/challenge && \
    chmod 4755 /challenge/challenge && \
    chmod 644 /challenge/challenge.c

# README (keep your big one if you want; this just ensures it exists/readable)
RUN echo "Read /challenge/README.md for guide." > /challenge/README.md && chmod 644 /challenge/README.md

# Helper script
RUN printf '%s\n' \
'#!/bin/bash' \
'echo "Dojo 1: ret2win - Quick Reference"' \
'echo "  /challenge/challenge"' \
'echo "  cat /challenge/README.md"' \
> /usr/local/bin/help && chmod 755 /usr/local/bin/help

# Entrypoint
COPY entrypoint.sh /root/.entrypoint.sh
RUN chmod 700 /root/.entrypoint.sh
ENTRYPOINT ["/root/.entrypoint.sh"]

EXPOSE 7681
ENTRYPOINT ["/entrypoint.sh"]