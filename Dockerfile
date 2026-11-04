# Build stage: compile the CLI into one self-contained file. Both base images
# are pinned by digest (Dependabot's docker ecosystem proposes the bumps).
FROM node:26-alpine@sha256:c6ad9e9c1d80f6eb607c26b4b0a132ff7a2344fad1c78ea3baa2a7d4c8de6d94 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build:lib

# Runtime stage: distroless Node and the bundled CLI, nothing else. The trust
# anchors are compiled into the bundle; a trust list is mounted at run time:
#   docker run --rm -v "$PWD:/data" ghcr.io/minutenotary/sealed-pdf-verify \
#     document.pdf --proof document.proof.json --trust issuers.json
FROM gcr.io/distroless/nodejs22-debian12:nonroot@sha256:13593b7570658e8477de39e2f4a1dd25db2f836d68a0ba771251572d23bb4f8e
COPY --from=build /app/dist/cli.js /app/dist/cli.js
WORKDIR /data
ENTRYPOINT ["/nodejs/bin/node", "/app/dist/cli.js"]
CMD ["--help"]
