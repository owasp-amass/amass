FROM golang:1.21-alpine as engine
RUN apk --no-cache add git
RUN go install -v github.com/owasp-amass/engine/...@develop

FROM golang:1.21-alpine as build
RUN apk --no-cache add git
WORKDIR /go/src/github.com/owasp-amass/amass
COPY . .
COPY --from=engine /go/bin/amass_engine ./resources/amass_engine
RUN go install -v ./...

FROM alpine:latest
RUN apk add --no-cache syslog-ng
RUN apk add --no-cache bash ca-certificates
#RUN apk add --no-cache busybox-openrc
#RUN rc-update add syslog boot
RUN apk --no-cache --update upgrade
COPY ./container-files /
COPY --from=build /go/bin/amass /bin/amass
ENV HOME /
RUN addgroup user \
    && adduser user -D -G user \
    && mkdir /.config \
    && chown user:user /.config \
    && mkdir /.config/amass \
    && chown user:user /.config/amass \
    && mkdir /data \
    && chown user:user /data
USER user
WORKDIR /data
STOPSIGNAL SIGINT
ENTRYPOINT ["/bin/amass"]
