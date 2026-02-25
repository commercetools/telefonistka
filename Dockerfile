FROM alpine:latest AS alpine-release
COPY telefonistka /usr/local/bin/telefonistka
USER 1001
ENTRYPOINT ["telefonistka"]
CMD ["server"]

FROM scratch
COPY telefonistka /usr/local/bin/telefonistka
USER 1001
ENTRYPOINT ["/usr/local/bin/telefonistka"]
CMD ["server"]
