FROM --platform=$BUILDPLATFORM golang:1.22.3 as test
ARG GOPROXY
ENV GOPATH=/go
ENV PATH="$PATH:$GOPATH/bin"
WORKDIR /go/src/github.com/wayfair-incubator/telefonistka
COPY . ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    go mod download
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    make test

FROM --platform=$BUILDPLATFORM test as build
ARG GOPROXY
ENV GOPATH=/go
ENV PATH="$PATH:$GOPATH/bin"
WORKDIR /go/src/github.com/wayfair-incubator/telefonistka
COPY . ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    go mod download
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    make build


FROM alpine:latest as alpine-release
WORKDIR /telefonistka
COPY --from=build /go/src/github.com/wayfair-incubator/telefonistka/telefonistka /telefonistka/bin/telefonistka
COPY templates/ /telefonistka/templates/
# This next line is hack to overcome GH actions lack of support for docker workdir override https://github.com/actions/runner/issues/878
COPY templates/ /github/workspace/templates/
USER 1001
ENTRYPOINT ["/telefonistka/bin/telefonistka"]
CMD ["server"]



FROM scratch
ENV wf_version="0.0.5"
ENV wf_description="K8s team GitOps prmoter webhook server"
WORKDIR /telefonistka
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /go/src/github.com/wayfair-incubator/telefonistka/telefonistka /telefonistka/bin/telefonistka
COPY templates/ /telefonistka/templates/
# This next line is hack to overcome GH actions lack of support for docker workdir override https://github.com/actions/runner/issues/878
COPY templates/ /github/workspace/templates/
USER 1001
ENTRYPOINT ["/telefonistka/bin/telefonistka"]
CMD ["server"]

