# Build Ghpb in a stock Go builder container
FROM golang:alpine as builder
RUN apk add --no-cache make git gcc musl-dev linux-headers

ADD . /go-hpb

RUN cd /go-hpb && make ghpb
# Pull Ghpb into a second stage deploy alpine container
FROM alpine:latest
RUN echo "https://mirror.tuna.tsinghua.edu.cn/alpine/v3.4/main/" > /etc/apk/repositories

RUN apk update \
        && apk upgrade \
        && apk add --no-cache bash \
        bash-doc \
        bash-completion \
        && rm -rf /var/cache/apk/* \
        && /bin/bash
RUN apk add --no-cache ca-certificates
COPY --from=builder /go-hpb/build/bin/ghpb /usr/local/bin/
COPY --from=builder /go-hpb/build/bin/iperf3 /
EXPOSE 8545 8546 30303 30303/udp
ENTRYPOINT ["ghpb"]
