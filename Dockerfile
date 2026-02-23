FROM alpine:latest AS alpine-release
WORKDIR /telefonistka
COPY telefonistka /telefonistka/bin/telefonistka
USER 1001
ENTRYPOINT ["/telefonistka/bin/telefonistka"]
CMD ["server"]

FROM scratch
COPY telefonistka /telefonistka/bin/telefonistka
USER 1001
ENTRYPOINT ["/telefonistka/bin/telefonistka"]
CMD ["server"]
