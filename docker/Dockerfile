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

# Rizin 0.4.0-git
RUN cd /opt                                               && \
    git clone https://github.com/rizinorg/rizin.git       && \
    cd /opt/rizin                                         && \
    git checkout cd6bde4aeb3221fb336b9df6080d4477d4fc0e78 && \
    meson build                                           && \
    ninja -C build install

# Rizin fix
RUN cp \
    /opt/rizin/librz/include/rz_util/rz_bitvector.h \
    /usr/local/include/librz/rz_util

# Ghidra
RUN cd /opt                                                      && \
    wget https://ghidra-sre.org/ghidra_9.2.3_PUBLIC_20210325.zip && \
    unzip ghidra_9.2.3_PUBLIC_20210325.zip                       && \
    rm ghidra_9.2.3_PUBLIC_20210325.zip

ENV GHIDRA_HOME=/opt/ghidra_9.2.3_PUBLIC
ENV LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu/

ARG USER_ID=1000
ARG GROUP_ID=1000

RUN groupadd --gid ${GROUP_ID} ubuntu \
    && useradd --uid ${USER_ID} --gid ubuntu --shell /bin/bash --create-home ubuntu
RUN echo "ubuntu ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/ubuntu && \
    chmod 0440 /etc/sudoers.d/ubuntu

USER    ubuntu
WORKDIR /home/ubuntu

ENV PYTHONUNBUFFERED=1
ENV PATH=$PATH:/home/ubuntu/.local/bin

# Other dependencies
RUN pip install networkx==2.5.1 \
                yapsy           \
                angr==9.0.8021  \
                rzpipe          \
                pydot==1.4.2    \
                pyyaml

# Androguard
RUN git clone https://github.com/androguard/androguard.git /tmp/androguard && \
    cd /tmp/androguard                                                     && \
    git checkout 8d091cbb309c0c50bf239f805cc1e0931b8dcddc                  && \
    pip install .                                                          && \
    rm -rf /tmp/androguard
