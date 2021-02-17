FROM golang:alpine as build
RUN apk --no-cache add git
RUN go get github.com/OWASP/Amass/cmd/amass

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=build /go/bin/amass /bin/amass
COPY --from=build /go/src/github.com/OWASP/Amass/examples/wordlists/ /wordlists/
ENV HOME /
ENTRYPOINT ["/bin/amass"]
