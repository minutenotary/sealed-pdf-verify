# Build stage: compile the CLI into one self-contained file. Both base images
# are pinned by digest (Dependabot's docker ecosystem proposes the bumps).
FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS build
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
