FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod .
COPY main.go .
RUN go build -o dashboard main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/dashboard .

EXPOSE 8080
CMD ["./dashboard"]
