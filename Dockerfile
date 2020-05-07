FROM golang:1.14.2-alpine3.11 as build
RUN apk --no-cache add git
RUN go get github.com/OWASP/Amass; exit 0
ENV GO111MODULE on
WORKDIR /go/src/github.com/OWASP/Amass
RUN go install ./...

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=build /go/bin/amass /bin/amass
COPY --from=build /go/src/github.com/OWASP/Amass/examples/wordlists/ /wordlists/
ENV HOME /
ENTRYPOINT ["/bin/amass"]
