# Build stage: compile the CLI into one self-contained file.
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build:lib

# Runtime stage: distroless Node and the bundled CLI, nothing else. The trust
# anchors are compiled into the bundle; a trust list is mounted at run time:
#   docker run --rm -v "$PWD:/data" ghcr.io/OWNER/sealed-pdf-verify \
#     document.pdf --proof document.proof.json --trust issuers.json
FROM gcr.io/distroless/nodejs22-debian12:nonroot
COPY --from=build /app/dist/cli.js /app/dist/cli.js
WORKDIR /data
ENTRYPOINT ["/nodejs/bin/node", "/app/dist/cli.js"]
CMD ["--help"]
