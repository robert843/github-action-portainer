FROM golang:1.25-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY . .
RUN go mod tidy
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /portainer-deploy ./cmd/deploy

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /portainer-deploy .

RUN chmod +x portainer-deploy

ENTRYPOINT ["/root/portainer-deploy"]