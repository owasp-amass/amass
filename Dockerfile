FROM golang:1.24.2-alpine AS build
RUN apk --no-cache add git
WORKDIR /go/src/github.com/owasp-amass/amass
COPY . .
RUN go install -v ./...

FROM alpine:latest
RUN apk add --no-cache bash ca-certificates
RUN apk --no-cache --update upgrade
COPY --from=build /go/bin/oam_enum /bin/amass
COPY --from=build /go/bin/amass_engine /bin/engine
COPY --from=build /go/bin/ae_isready /bin/ae_isready
COPY --from=build /go/bin/oam_subs /bin/subs
COPY --from=build /go/bin/oam_assoc /bin/assoc
COPY --from=build /go/bin/oam_viz /bin/viz
COPY --from=build /go/bin/oam_track /bin/track
COPY --from=build /go/bin/oam_i2y /bin/i2y
ENV HOME=/
RUN addgroup user \
    && adduser user -D -G user \
    && mkdir /.config \
    && chown user:user /.config \
    && mkdir /.config/amass \
    && chown user:user /.config/amass \
    && mkdir /data \
    && chown user:user /data
USER user
WORKDIR /data
STOPSIGNAL SIGINT
ENTRYPOINT ["/bin/amass"]