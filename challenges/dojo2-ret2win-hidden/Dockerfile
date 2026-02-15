FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc \
    gdb \
    binutils \
    file \
    python3 \
    python3-pip \
    netcat \
    ttyd \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Create challenge directory
RUN mkdir -p /challenge

# Create hacker user (UID 1000)
RUN useradd -m -u 1000 -s /bin/bash hacker

# Copy challenge sources and docs
COPY challenge.c /challenge/challenge.c
COPY README.md /challenge/README.md

# Build challenge binary (SUID root, no PIE, no canary, execstack)
RUN gcc /challenge/challenge.c -o /challenge/challenge \
    -fno-stack-protector -z execstack -no-pie -O0 -g

# Set ownership and SUID bit
RUN chown root:root /challenge/challenge && chmod 4755 /challenge/challenge

# Copy hidden entrypoint to root-only location
COPY entrypoint.sh /root/.entrypoint.sh
RUN chmod 700 /root/.entrypoint.sh && chown root:root /root/.entrypoint.sh

# Restrict /root from non-root users (keeps entrypoint hidden)
RUN chmod 0700 /root

EXPOSE 7681

CMD ["/root/.entrypoint.sh"]