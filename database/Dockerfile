# Create from official mysql image
# FROM mysql:latest
FROM mcr.microsoft.com/mssql/server:2019-latest

# Add a database
#ENV MYSQL_DATABASE crypto_db
#ENV MYSQL_ROOT_PASSWORD Pa$$w0rd

#USER root

#COPY db_.sql db_.sql
#COPY import-data.sh import-data.sh
#COPY entrypoint.sh entrypoint.sh

#RUN chmod +x entrypoint.sh

#USER mssql
#CMD /bin/bash ./entrypoint.sh

# Initial db scripts
#COPY db_.sql /docker-entrypoint-initdb.d/db_.sql
USER root

RUN mkdir -p /usr/config

# Bundle config source
COPY . /usr/config

WORKDIR /usr/config

# Grant permissions for to our scripts to be executable
RUN chmod +x /usr/config/entrypoint.sh
RUN chmod +x /usr/config/configure-db.sh

ENTRYPOINT ["/usr/config/entrypoint.sh"]
