FROM docker.io/golang:1.26.1-alpine AS deps
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

FROM deps AS build-ssh-gateway
COPY api/ api/
COPY internal/ internal/
COPY cmd/ssh-gateway/ cmd/ssh-gateway/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/ssh-gateway ./cmd/ssh-gateway

FROM deps AS build-blip-controller
COPY internal/ internal/
COPY cmd/blip-controller/ cmd/blip-controller/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/blip-controller ./cmd/blip-controller

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build-ssh-gateway /out/ssh-gateway /usr/local/bin/ssh-gateway
COPY --from=build-blip-controller /out/blip-controller /usr/local/bin/blip-controller

EXPOSE 2222 8080
ENTRYPOINT ["/usr/local/bin/ssh-gateway"]
