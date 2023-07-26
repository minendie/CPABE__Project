FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

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
                curl \
                #libmysqlclient-dev \
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

RUN apt-get update

RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -

RUN curl https://packages.microsoft.com/config/ubuntu/20.04/prod.list > /etc/apt/sources.list.d/mssql-release.list
# RUN exit

RUN apt-get update
RUN ACCEPT_EULA=Y apt-get install -y msodbcsql17
# optional: for bcp and sqlcmd
RUN ACCEPT_EULA=Y apt-get install -y mssql-tools
RUN echo 'export PATH="$PATH:/opt/mssql-tools/bin"' >> ~/.bashrc
#RUN echo 'source ~/.bashrc' >> ~/.bashrc

RUN apt-get -qq update
RUN apt-get install -yqq unixodbc-dev
# optional: for unixODBC development headers
RUN apt-get -yqq clean

WORKDIR /home/server
# COPY demo_db2.xlsx demo_db2.xlsx
COPY read_excel.py read_excel.py
COPY encrypt_table.py encrypt_table.py
COPY generate_key.py generate_key.py
COPY pki_helpers.py pki_helpers.py
COPY register_user.py register_user.py
COPY aes_gcm_128_helpers.py aes_gcm_128_helpers.py
COPY cp_abe_services.py cp_abe_services.py
COPY multisocat.py multisocat.py
COPY receive_revoke.py receive_revoke.py
COPY update_CT.py update_CT.py
COPY webapp.py webapp.py
COPY templates templates
#RUN pip3 install pandas sqlalchemy openpyxl pyodbc cryptography pymssql
RUN pip3 install openpyxl pyodbc cryptography pymssql pwntools pycryptodome mysql-connector-python flask python-dotenv

RUN python3 generate_key.py

EXPOSE 5000

#RUN python3 read_excel2.py
CMD python3 multisocat.py