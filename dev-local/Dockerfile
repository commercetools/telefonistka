FROM golang:1.22.3 AS build
WORKDIR /
COPY ../ .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 go install -ldflags "-s -w -extldflags '-static'" github.com/go-delve/delve/cmd/dlv@latest
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=linux CGO_ENABLED=0 go build -gcflags "all=-N -l" -o ./telefonistka .

FROM alpine
WORKDIR /
COPY ../ .
COPY --from=build /go/bin/dlv dlv
COPY --from=build /telefonistka telefonistka
ENTRYPOINT [ "/dlv" , "--listen=:40000", "--headless=true", "--api-version=2", "--accept-multiclient", "exec", "/telefonistka", "server"]
