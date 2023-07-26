FROM ubuntu:20.04

ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install -y --no-install-recommends \
                gcc \
                bison \
                flex \
                git \
                make \
                libc6-dev \
                libgmp-dev \
                libssl-dev \
                wget \
                ca-certificates \
        && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y python3-distutils python3-pip python3-venv

ENV LIBRARY_PATH /usr/local/lib
ENV LD_LIBRARY_PATH /usr/local/lib
ENV LIBRARY_INCLUDE_PATH /usr/local/include

# PBC
COPY --from=initc3/pbc:0.5.14-buster \
                /usr/local/include/pbc \
                /usr/local/include/pbc
COPY --from=initc3/pbc:0.5.14-buster \
                /usr/local/lib/libpbc.so.1.0.0  \
                /usr/local/lib/libpbc.so.1.0.0
RUN set -ex \
    && cd /usr/local/lib \
    && ln -s libpbc.so.1.0.0 libpbc.so \
    && ln -s libpbc.so.1.0.0 libpbc.so.1

# Setup virtualenv
ENV PYTHON_LIBRARY_PATH /opt/venv
ENV PATH ${PYTHON_LIBRARY_PATH}/bin:${PATH}

RUN apt-get update && apt-get install socat build-essential curl -y
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
RUN echo 'source $HOME/.cargo/env' >> $HOME/.bashrc

RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install cryptography pwntools

WORKDIR /home/log_node
COPY savelog.py savelog.py
COPY multisocat.py multisocat.py

CMD python3 multisocat.py

