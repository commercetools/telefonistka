FROM alpine:latest
WORKDIR /srv
COPY templates/ /srv/templates/
COPY telefonistka /usr/local/bin
USER 1001
ENTRYPOINT ["/usr/local/bin/telefonistka"]
CMD ["server"]

