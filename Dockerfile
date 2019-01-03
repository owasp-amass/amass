FROM golang:alpine as build
WORKDIR /go/src/github.com/OWASP/Amass
COPY . .
RUN apk --no-cache add git \
  && go get -u github.com/OWASP/Amass/...
  
FROM alpine:latest
COPY --from=build /go/bin/amass /bin/amass
COPY --from=build /go/bin/amass.db /bin/amass.db
COPY --from=build /go/bin/amass.netdomains /bin/amass.netdomains
COPY --from=build /go/bin/amass.viz /bin/amass.viz
ENTRYPOINT ["/bin/amass"]
