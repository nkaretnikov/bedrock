# syntax=docker/dockerfile:1
#
# Bitcoin Core node + bedrock-miner, statically built so the runtime layer
# has no extra libc dependencies.

FROM alpine:3.20 AS build
RUN apk add --no-cache gcc musl-dev
COPY miner.c /src/miner.c
RUN gcc -O2 -static -o /bedrock-miner /src/miner.c

FROM docker.io/bitcoin/bitcoin:latest
COPY --from=build /bedrock-miner /usr/local/bin/bedrock-miner
ENTRYPOINT ["/usr/local/bin/bedrock-miner"]
