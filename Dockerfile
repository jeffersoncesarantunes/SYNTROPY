FROM alpine:3.24 AS builder
RUN apk add --no-cache gcc musl-dev make ncurses-dev linux-headers
WORKDIR /src
COPY . ./
RUN make -C K-Scanner clean && make -C K-Scanner
RUN make -C LinSpec clean && make -C LinSpec

FROM alpine:3.24
RUN apk add --no-cache bash python3 coreutils file findutils binutils
COPY --from=builder /src/K-Scanner/kscanner /usr/local/bin/kscanner
COPY --from=builder /src/LinSpec/linspec /usr/local/bin/linspec
COPY --from=builder /src/S.I.R.E.N /opt/siren
COPY scripts/ /usr/local/bin/
WORKDIR /opt/syntropy
ENTRYPOINT ["/usr/local/bin/syntropy-run.sh"]
