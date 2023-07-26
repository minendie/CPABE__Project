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
# RUN python3 -m pip install cryptography pwntools
RUN pip3 install openpyxl pyodbc cryptography pwntools pycryptodome mysql-connector-python flask python-dotenv

#COPY pki_helpers.py /home/attr-auth/pki_helpers.py
#COPY keygen.py /home/attr-auth/keygen.py
#COPY server.py /home/attr-auth/server.py
#COPY getcert.py /home/attr-auth/getcert.py

#CMD ["python3", "/home/attr-auth/keygen.py"]

#CMD ["socat", "-u", "FILE:\"/home/attr-auth/server-csr.pem\"", \
#        "TCP-LISTEN:1338,reuseaddr,fork"]

WORKDIR /home/duser
COPY pki_helpers.py pki_helpers.py
COPY generate_key.py generate_key.py
COPY register_user.py register_user.py
COPY decrypt_table.py decrypt_table.py
COPY aes_gcm_128_helpers.py aes_gcm_128_helpers.py
COPY cp_abe_services.py cp_abe_services.py
COPY webapp.py webapp.py
COPY templates templates

RUN python3 generate_key.py

EXPOSE 5000
#CMD socat EXEC:"cat user-csr.pem",stderr TCP-LISTEN:1339,fork,reuseaddr
#CMD python3 webapp.py