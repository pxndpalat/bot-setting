FROM golang:1.25-alpine AS build

WORKDIR /src

COPY go.mod ./
COPY main.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/webhook .

FROM alpine:3.22

RUN apk add --no-cache ca-certificates

COPY --from=build /out/webhook /usr/local/bin/webhook

EXPOSE 3000

ENTRYPOINT ["webhook"]
