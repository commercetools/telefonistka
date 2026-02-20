
FROM golang:1.26 AS test
ARG GOPROXY
ENV GOPATH=/go
ENV PATH="$PATH:$GOPATH/bin"
WORKDIR /go/src/github.com/commercetools/telefonistka
COPY . ./
RUN make test

FROM test AS build
ARG GOPROXY
ENV GOPATH=/go
ENV PATH="$PATH:$GOPATH/bin"
WORKDIR /go/src/github.com/commercetools/telefonistka
COPY . ./
RUN make build


FROM alpine:latest AS alpine-release
WORKDIR /telefonistka
COPY --from=build /go/src/github.com/commercetools/telefonistka/telefonistka /telefonistka/bin/telefonistka
COPY templates/ /telefonistka/templates/
# This next line is hack to overcome GH actions lack of support for docker workdir override https://github.com/actions/runner/issues/878
COPY templates/ /github/workspace/templates/
USER 1001
ENTRYPOINT ["/telefonistka/bin/telefonistka"]
CMD ["server"]



FROM scratch
WORKDIR /telefonistka
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /go/src/github.com/commercetools/telefonistka/telefonistka /telefonistka/bin/telefonistka
COPY templates/ /telefonistka/templates/
# This next line is hack to overcome GH actions lack of support for docker workdir override https://github.com/actions/runner/issues/878
COPY templates/ /github/workspace/templates/
USER 1001
ENTRYPOINT ["/telefonistka/bin/telefonistka"]
CMD ["server"]

