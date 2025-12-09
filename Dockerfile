FROM golang:1.25-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /portainer-deploy ./cmd/deploy

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /portainer-deploy .
COPY entrypoint.sh .

RUN chmod +x entrypoint.sh

ENTRYPOINT ["/root/entrypoint.sh"]