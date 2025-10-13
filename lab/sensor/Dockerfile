# Sensor box — builds respounder from source and runs the detector.
# Build context is the repository root (see docker-compose.yml).
FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /respounder .

FROM debian:bookworm-slim
COPY --from=build /respounder /usr/local/bin/respounder
# Random hostnames, both protocols, fast interval, verbose probe logging.
CMD ["respounder", "-interface", "eth0", "-random", "-protocol", "both", "-interval", "5s", "-v"]
