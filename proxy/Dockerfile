# docker build -t provenza-proxy proxy/
FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /provenza-proxy . && mkdir -p /state

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /provenza-proxy /provenza-proxy
COPY --from=build --chown=65532:65532 /state /var/lib/provenza-proxy
USER nonroot:nonroot
# state_dir (the proxy's signing key, receipt log, last verified signed policy):
# mount a volume here, e.g. docker run -v provenza-proxy:/var/lib/provenza-proxy
VOLUME /var/lib/provenza-proxy
ENTRYPOINT ["/provenza-proxy"]
