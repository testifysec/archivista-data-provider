ARG BASEIMAGE="cgr.dev/chainguard/static"

FROM ${BASEIMAGE}

WORKDIR /

COPY provider .

COPY --chown=65532:65532 ./certs/tls.crt \
    ./certs/tls.key \
    /certs/

USER 65532:65532

ENTRYPOINT ["/provider"]
