FROM golang:1.21-alpine AS builder

WORKDIR /build

COPY . .

RUN go build ./cmd/proxy/main.go

FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get -y install postgresql postgresql-contrib ca-certificates

USER postgres

COPY /scripts /opt/scripts

RUN service postgresql start && \
        psql -c "CREATE USER admin WITH superuser login password 'admin';" && \
        psql -c "ALTER ROLE admin WITH PASSWORD 'admin';" && \
        createdb -O admin vk && \
        psql -f ./opt/scripts/sql/init_db.sql -d vk && \
        service postgresql stop

VOLUME ["/etc/postgresql", "/var/log/postgresql", "/var/lib/postgresql"]

USER root

WORKDIR /proxy
COPY --from=builder /build/main .

COPY . .

EXPOSE 8080
EXPOSE 8000
EXPOSE 5432

ENV PROXY_PORT=8080
ENV REPEATER_PORT=8000
ENV DB_USER=user
ENV DB_NAME=Requests
#
#RUN ["chmod", "777", "/opt/scripts/gen_ca.sh"]
#RUN ["chmod", "777", "/opt/scripts/gen_cert.sh"]
#RUN ["chmod", "777", "/opt/scripts/install_ca.sh"]

RUN #bash  "/opt/scripts/gen_ca.sh" && \
#    bash "/opt/scripts/gen_cert.sh" && \
#    bash "/opt/scripts/install_ca.sh"

#ENTRYPOINT ["sh", "/opt/scripts/bash/generate_ca.sh"]
#ENTRYPOINT ["sh", "/opt/scripts/bash/install_ca.sh"]

CMD service postgresql start && ./main