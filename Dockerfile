FROM golang:1.26rc2-alpine3.23 AS build-env

WORKDIR /go/src/slack-mcp-server

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG GITHUB_SHA=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.GitCommit=${GITHUB_SHA}" -o /go/bin/mcp-server ./cmd/slack-mcp-server

FROM build-env AS dev

RUN go install github.com/go-delve/delve/cmd/dlv@v1.25.0 && cp /go/bin/dlv /dlv

WORKDIR /app/mcp-server

EXPOSE 3001

ENTRYPOINT ["mcp-server"]
CMD ["--transport", "sse"]

FROM alpine:3.23.3 AS production

RUN apk --no-cache add ca-certificates net-tools curl

COPY --from=build-env /go/bin/mcp-server /usr/local/bin/mcp-server

WORKDIR /app

USER 65534:65534

EXPOSE 3001

ENTRYPOINT ["mcp-server"]
CMD ["--transport", "sse"]
