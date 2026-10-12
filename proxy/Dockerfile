# docker build -t provenza-proxy proxy/
FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /provenza-proxy .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /provenza-proxy /provenza-proxy
USER nonroot:nonroot
ENTRYPOINT ["/provenza-proxy"]
