FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y      \
    ninja-build             \
    openjdk-11-jdk-headless \
    python                  \
    python3-pip             \
    sudo                    \
    git                     \
    curl                    \
    wget                    \
    unzip                   \
    pkg-config

RUN pip install meson

# Rizin 0.2.1
RUN cd /opt                                               && \
    git clone https://github.com/rizinorg/rizin.git       && \
    cd /opt/rizin                                         && \
    git checkout 91d3bb43fd92fc04e8def76beb22c2d84ae53fb5 && \
    meson build                                           && \
    ninja -C build install

# Ghidra
RUN cd /opt                                                      && \
    wget https://ghidra-sre.org/ghidra_9.2.3_PUBLIC_20210325.zip && \
    unzip ghidra_9.2.3_PUBLIC_20210325.zip                       && \
    rm ghidra_9.2.3_PUBLIC_20210325.zip

ENV GHIDRA_HOME=/opt/ghidra_9.2.3_PUBLIC
ENV LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu/

RUN groupadd --gid 1000 ubuntu \
    && useradd --uid 1000 --gid ubuntu --shell /bin/bash --create-home ubuntu
RUN echo "ubuntu ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/ubuntu && \
    chmod 0440 /etc/sudoers.d/ubuntu

USER    ubuntu
WORKDIR /home/ubuntu

# Androguard
RUN git clone https://github.com/androguard/androguard.git /tmp/androguard && \
    cd /tmp/androguard                                                     && \
    pip install .                                                          && \
    rm -rf /tmp/androguard

# Other dependencies
RUN pip install networkx \
                yapsy    \
                angr     \
                rzpipe   \
                pydot    \
                pyyaml
