FROM golang:1.15-alpine as build
RUN apk --no-cache add git
RUN go get -d -v github.com/OWASP/Amass/v3/...
WORKDIR /go/src/github.com/OWASP/Amass
RUN go install -v ./...

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=build /go/bin/amass /bin/amass
COPY --from=build /go/src/github.com/OWASP/Amass/examples/wordlists/ /wordlists/
ENV HOME /
ENTRYPOINT ["/bin/amass"]
