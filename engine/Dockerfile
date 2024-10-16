FROM golang:1.23-alpine AS build
RUN apk --no-cache add git
WORKDIR /go/src/github.com/owasp-amass/engine
COPY . .
RUN go install -v ./...

FROM alpine:latest
RUN apk add --no-cache bash ca-certificates nfs-utils
RUN apk --no-cache --update upgrade
COPY --from=build /go/bin/amass_engine /bin/engine
COPY --from=build /go/bin/ae_isready /bin/ae_isready
ENV HOME=/
RUN addgroup user \
    && adduser user -D -G user \
    && mkdir /.config \
    && mkdir /.config/amass \
    && chown -R user:user /.config/amass
USER user
WORKDIR /.config/amass
STOPSIGNAL SIGINT
HEALTHCHECK --interval=10s --timeout=5s --retries=25 \
  CMD ae_isready --host 127.0.0.1
ENTRYPOINT ["/bin/engine"]