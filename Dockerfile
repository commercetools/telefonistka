FROM golang:1.26 AS test
ARG GOPROXY
WORKDIR /go/src/github.com/commercetools/telefonistka
COPY . ./
RUN go generate $(go list ./mocks/...) && go test -v -timeout 30s ./...

FROM test AS build
RUN CGO_ENABLED=0 go build -ldflags '-extldflags "-static"' -o telefonistka ./cmd/telefonistka


FROM alpine:latest AS alpine-release
WORKDIR /telefonistka
COPY --from=build /go/src/github.com/commercetools/telefonistka/telefonistka /telefonistka/bin/telefonistka
USER 1001
ENTRYPOINT ["/telefonistka/bin/telefonistka"]
CMD ["server"]



FROM scratch
WORKDIR /telefonistka
COPY --from=build /go/src/github.com/commercetools/telefonistka/telefonistka /telefonistka/bin/telefonistka
USER 1001
ENTRYPOINT ["/telefonistka/bin/telefonistka"]
CMD ["server"]

