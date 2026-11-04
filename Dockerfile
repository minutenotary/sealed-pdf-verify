# Build stage: compile the CLI into one self-contained file.
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build:lib

# Runtime stage: distroless Node, only the bundled CLI and the trust files.
FROM gcr.io/distroless/nodejs22-debian12:nonroot
WORKDIR /app
COPY --from=build /app/dist/cli.js /app/dist/cli.js
COPY --from=build /app/trust /app/trust
COPY --from=build /app/tsa-roots /app/tsa-roots
COPY --from=build /app/package.json /app/package.json
WORKDIR /data
ENTRYPOINT ["/nodejs/bin/node", "/app/dist/cli.js"]
CMD ["--help"]
