FROM golang:1.16-alpine as build
RUN apk --no-cache add git
ENV GO111MODULE on
RUN go get -v github.com/OWASP/Amass/v3/...

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=build /go/bin/amass /bin/amass
ENV HOME /
ENTRYPOINT ["/bin/amass"]
