FROM golang:1.16-alpine as build
RUN apk --no-cache add git
WORKDIR /go/src/github.com/OWASP/Amass
COPY . .
RUN go install -v ./...

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=build /go/bin/amass /bin/amass
ENV HOME /
ENTRYPOINT ["/bin/amass"]
