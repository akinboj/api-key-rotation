FROM golang:1.20-alpine3.17

# Configure build options
ARG IMAGE_BUILD_TIMESTAMP
ENV IMAGE_BUILD_TIMESTAMP=${IMAGE_BUILD_TIMESTAMP}
RUN echo IMAGE_BUILD_TIMESTAMP=${IMAGE_BUILD_TIMESTAMP}

# Install required dependencies
RUN apk add --no-cache curl \
    ca-certificates \
    tzdata \ 
    && rm -rf /var/cache/apk/*

ENV TZ="Australia/Sydney"

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .

RUN go build -o jwk-service .

RUN mkdir -p /app/certs

CMD ["./jwk-service"]