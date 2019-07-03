FROM golang:1.12.6-alpine3.10 as build
RUN apk --no-cache add git
RUN go get github.com/OWASP/Amass; exit 0
ENV GO111MODULE on
WORKDIR /go/src/github.com/OWASP/Amass
RUN go install ./...

FROM alpine:latest
COPY --from=build /go/bin/amass /bin/amass
COPY --from=build /go/src/github.com/OWASP/Amass/wordlists/ /wordlists/
ENV HOME /
ENTRYPOINT ["/bin/amass"]
