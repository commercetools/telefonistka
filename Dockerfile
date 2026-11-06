FROM alpine:latest@sha256:3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a AS alpine-release
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
