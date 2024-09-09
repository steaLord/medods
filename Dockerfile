FROM golang:alpine AS builder

WORKDIR /build

ADD go.mod .

COPY . .

RUN go build -o authentication-service

FROM alpine

WORKDIR /build

COPY --from=builder /build/authentication-service /build/authentication-service

CMD ["./authentication-service"]