# syntax=docker/dockerfile:1.3-labs

#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#

FROM golang:1.17-alpine AS builder

WORKDIR /go/src/github.com/OWASP/Amass
COPY . .

ENV GO111MODULE=on
RUN <<eot
#!/bin/ash
apk add -U git subversion
go install -v ./...
svn checkout https://github.com/OWASP/Amass/trunk/examples/wordlists /wordlists
eot

#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#

FROM alpine:latest AS final

COPY --from=builder /go/bin/amass /usr/local/bin/
COPY --from=builder /wordlists/*.txt /wordlists/

COPY LICENSE /

RUN <<eot
#!/bin/ash
apk add --no-cache -U ca-certificates
mkdir -p /root/.config/amass
ln -sf /root/.config/amass /amass
eot

WORKDIR /amass

SHELL [ "/bin/ash", "-c" ]
ENTRYPOINT [ "amass" ]
CMD [ "-help" ]
