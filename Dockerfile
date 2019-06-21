FROM golang:1.12.6-alpine3.10 as build
RUN apk --no-cache add git
RUN go get github.com/OWASP/Amass/...
WORKDIR /go/src/github.com/OWASP/Amass
ENV GO111MODULE on
RUN go get ./...
RUN go install ./...

FROM alpine:latest
COPY --from=build /go/bin/amass /bin/amass
COPY --from=build /go/src/github.com/OWASP/Amass/wordlists/ /wordlists/
ENV HOME /
ENTRYPOINT ["/bin/amass"]
