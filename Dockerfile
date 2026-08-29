FROM node:24-bookworm-slim AS ui
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend ./
COPY internal/web /src/internal/web
RUN npm run build

FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
COPY --from=ui /src/internal/web/dist ./internal/web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/fyke ./cmd/fyke

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/fyke /usr/local/bin/fyke
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/fyke"]
