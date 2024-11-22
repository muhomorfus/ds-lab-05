FROM golang:1.23.2

LABEL org.opencontainers.image.source=https://github.com/muhomorfus/ds-lab-04
LABEL org.opencontainers.image.description="DS labs image"
LABEL org.opencontainers.image.licenses=MIT

COPY . /build
WORKDIR /build

RUN go mod tidy
RUN go build -o /opt/reservation /build/reservation/cmd/service/main.go
RUN go build -o /opt/library /build/library/cmd/service/main.go
RUN go build -o /opt/rating /build/rating/cmd/service/main.go
RUN go build -o /opt/gateway /build/gateway/cmd/service/main.go
