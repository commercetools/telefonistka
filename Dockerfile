FROM alpine:latest@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS alpine-release
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
