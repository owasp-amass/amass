FROM golang:1.21-alpine AS build
RUN apk --no-cache add git
WORKDIR /go/src/github.com/owasp-amass/amass
COPY . .
RUN go install -v ./...

FROM alpine:latest
RUN apk add --no-cache bash ca-certificates
RUN apk --no-cache --update upgrade
COPY --from=build /go/bin/amass /bin/amass
ENV HOME=/
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