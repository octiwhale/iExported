# Always use the native platform of the host for the compiler
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .

# Initialize and fetch dependencies
RUN if [ ! -f go.mod ]; then go mod init iexported; fi
RUN go mod tidy

# These ARGs are automatically filled by docker buildx
ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o iexported main.go

# run stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

# copy the binary
COPY --from=builder /app/iexported .

COPY static/ ./static/
COPY entrypoint.sh /root/entrypoint.sh
RUN chmod +x /root/entrypoint.sh

RUN mkdir /root/data
EXPOSE 8765
ENTRYPOINT ["/root/entrypoint.sh"]
CMD ["./iexported"]