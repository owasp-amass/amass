FROM golang:alpine as build
WORKDIR /go/src/github.com/OWASP/Amass
COPY . .
RUN apk --no-cache add git \
  && go get -u -v golang.org/x/vgo \
  && vgo install
  
FROM alpine:latest
COPY --from=build /go/bin/Amass /bin/amass 
ENTRYPOINT ["/bin/amass"]
