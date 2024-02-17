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
RUN apk --no-cache add ca-certificates
COPY --from=build /go/bin/amass /bin/amass
ENV HOME /
RUN addgroup user \
    && adduser user -D -G user \
    && mkdir /.config \
    && mkdir /.config/amass \
    && chown -R user:user /.config/amass
USER user
ENTRYPOINT ["/bin/amass"]
