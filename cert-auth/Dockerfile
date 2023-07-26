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

# Install charm
# Creates /charm/dist/Charm_Crypto...x86_64.egg, which gets copied into the venv
# /opt/venv/lib/python3.7/site-packages/Charm_crypto...x86_64.egg
RUN set -ex \
        \
        && mkdir -p /usr/src/charm \
        && git clone https://github.com/JHUISI/charm.git /usr/src/charm \
        && cd /usr/src/charm \
        && python3 -m venv ${PYTHON_LIBRARY_PATH} \
        && ./configure.sh \
        && make install \
        && rm -rf /usr/src/
        
RUN apt-get update && apt-get install socat build-essential curl -y
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
RUN echo 'source $HOME/.cargo/env' >> $HOME/.bashrc

RUN python3 -m pip install --upgrade pip

RUN python3 -m pip install cryptography pwntools

WORKDIR /home/cert-auth
#COPY pki_helpers.py /home/cert-auth/pki_helpers.py
#COPY certgen.py /home/cert-auth/certgen.py
#COPY server.py /home/cert-auth/server.py
#COPY signing_csr.py /home/cert-auth/signing_csr.py
#COPY sign_csr.sh /home/cert-auth/sign_csr.sh

#RUN chmod +x /home/cert-auth/sign_csr.sh
#CMD ["python3", "/home/cert-auth/certgen.py"]

# General purpose
COPY pki_helpers.py pki_helpers.py

# Certificate
COPY generate_certificate.py generate_certificate.py
COPY sign_csr.py sign_csr.py

# MAABE
COPY generate_global_key.py generate_global_key.py
COPY register_user.py register_user.py
COPY register_aa.py register_aa.py
COPY init.sh init.sh

COPY multisocat.py multisocat.py
# COPY abe_key_ca_aa.py abe_key_ca_aa.py

#RUN python3 generate_certificate.py
#RUN python3 generate_global_key.py
RUN chmod +x /home/cert-auth/init.sh

CMD ./init.sh
        