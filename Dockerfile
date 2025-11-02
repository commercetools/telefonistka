FROM alpine:latest AS alpine-release
WORKDIR /srv
COPY templates/ /srv/templates/
COPY telefonistka /usr/local/bin/
USER 1001
ENTRYPOINT ["/usr/local/bin/telefonistka"]
CMD ["server"]

FROM scratch
WORKDIR /srv
COPY --from=alpine-release /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY templates/ /srv/templates/
COPY telefonistka /usr/local/bin/
USER 1001
ENTRYPOINT ["/usr/local/bin/telefonistka"]
CMD ["server"]
