# ClamAV REST API

[ClamAV®](https://www.clamav.net/) is an open-source antivirus engine for detecting trojans, viruses, malware & other malicious threats. [download](https://www.clamav.net/downloads) The latest stable release is version 1.5.4.

This project provides a two-in-one Docker image that runs this engine, automatically updates virus definitions in the background via `freshclam`, and provides a stateless REST API interface to interact with the ClamAV process.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
    - [Synchronous File Scan](#synchronous-file-scan)
    - [Synchronous URL Scan](#synchronous-url-scan)
    - [Asynchronous Scanning (Webhooks)](#asynchronous-scanning-webhooks)
- [Admin API](#admin-api)
- [Status Codes](#status-codes)
- [Authentication](#authentication)
- [Configuration](#configuration)
- [Maintenance & Monitoring](#maintenance--monitoring)
- [Developing](#developing)

## Features

- **Multi-Stage Docker Builds**: Available in Alpine and Rocky Linux bases, optimized for minimal image sizes.
- **Synchronous & Asynchronous Scanning**: Support for standard multipart file uploads as well as stateless async scanning via webhooks (ideal for AWS ECS Fargate).
- **Cloud URL Scanning**: Stream files directly from remote URLs to ClamAV without buffering in memory.
- **API Key Authentication**: Optional security layer to restrict access.
- **Prometheus Metrics**: Built-in `/metrics` endpoint.

## Installation

You can pull the pre-built, automatically updated Docker image directly from Docker Hub:

```bash
docker pull amithalder/clamav-restapi:alpine-latest
```

*(Alternatively, to use the Rocky Linux variant, pull `amithalder/clamav-restapi:rocky-latest`)*

## Quick Start

Run the `clamav-restapi` docker image locally:
```bash
docker run -d -p 9000:9000 -p 9443:9443 --name clamav-restapi amithalder/clamav-restapi:alpine-latest
```

If you are deploying this on **AWS ECS Fargate** or want to configure it locally with custom limits and API keys, you can pass environment variables using `-e`:

**Using the default Alpine image (`latest`):**
```bash
docker run -d \
  -p 9000:9000 \
  -e API_KEY="my-secret-key" \
  -e ADMIN_API_KEY="my-admin-key" \
  -e CLAMD_PORT="tcp://localhost:3310" \
  -e MAX_FILE_SIZE="25M" \
  -e MAX_SCAN_SIZE="100M" \
  -e MAX_RECURSION="16" \
  -e MAX_FILES="10000" \
  -e MAX_EMBEDDEDPE="10M" \
  -e MAX_HTMLNORMALIZE="10M" \
  -e MAX_HTMLNOTAGS="2M" \
  -e MAX_SCRIPTNORMALIZE="5M" \
  -e MAX_ZIPTYPERCG="1M" \
  -e MAX_PARTITIONS="50" \
  -e MAX_ICONSPE="100" \
  -e PCRE_MATCHLIMIT="100000" \
  -e PCRE_RECMATCHLIMIT="2000" \
  -e SIGNATURE_CHECKS="24" \
  --name clamav-restapi \
  amithalder/clamav-restapi:alpine-latest
```

**Using the Rocky Linux (CentOS) image (`rocky-latest`):**
```bash
docker run -d \
  -p 9000:9000 \
  -e API_KEY="my-secret-key" \
  -e ADMIN_API_KEY="my-admin-key" \
  -e CLAMD_PORT="tcp://localhost:3310" \
  -e MAX_FILE_SIZE="25M" \
  -e MAX_SCAN_SIZE="100M" \
  -e MAX_RECURSION="16" \
  -e MAX_FILES="10000" \
  -e MAX_EMBEDDEDPE="10M" \
  -e MAX_HTMLNORMALIZE="10M" \
  -e MAX_HTMLNOTAGS="2M" \
  -e MAX_SCRIPTNORMALIZE="5M" \
  -e MAX_ZIPTYPERCG="1M" \
  -e MAX_PARTITIONS="50" \
  -e MAX_ICONSPE="100" \
  -e PCRE_MATCHLIMIT="100000" \
  -e PCRE_RECMATCHLIMIT="2000" \
  -e SIGNATURE_CHECKS="24" \
  --name clamav-restapi \
  amithalder/clamav-restapi:rocky-latest
```

### Synchronous File Scan

Test that the service detects a common test virus signature.

**HTTP:**
```bash
$ curl -i -F "file=@eicar.com.txt" http://localhost:9000/scan

HTTP/1.1 100 Continue
HTTP/1.1 406 Not Acceptable
Content-Type: application/json; charset=utf-8
Content-Length: 56

{ "status": "FOUND", "description": "Eicar-Test-Signature" }
```

Test that the service returns 200 for a clean file.

**HTTP:**
```bash
$ curl -i -F "file=@clean_file.txt" http://localhost:9000/scan

HTTP/1.1 100 Continue
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 33

{ "status": "OK", "description": "" }
```

### Synchronous URL Scan

You can pass a URL (e.g., an S3 pre-signed URL). The API will stream the file directly to ClamAV without buffering it in memory.

```bash
$ curl -i -X POST -H "Content-Type: application/json" -d '{"url":"https://secure.eicar.org/eicar.com.txt"}' http://localhost:9000/scan-url

HTTP/1.1 406 Not Acceptable
Content-Type: application/json; charset=utf-8
Content-Length: 56

{ "status": "FOUND", "description": "Eicar-Test-Signature" }
```

### Asynchronous Scanning (Webhooks)

For very large files, or deployments on stateless infrastructure like AWS ECS Fargate, you can use the asynchronous endpoints. These endpoints return a `202 Accepted` status immediately and process the file in the background.

Once the scan finishes, the container will send an HTTP POST request to your specified `webhook_url` containing the final scan result JSON.

**Async File Upload:**
```bash
curl -i -F "file=@eicar.com.txt" -F "webhook_url=https://your-webhook-endpoint.com/callback" http://localhost:9000/scan-async

HTTP/1.1 202 Accepted
Content-Type: application/json; charset=utf-8

{"scan_id":"uuid-string","message":"Scan started asynchronously"}
```

**Async URL Scan:**
```bash
curl -i -X POST -H "Content-Type: application/json" \
  -d '{"url":"https://secure.eicar.org/eicar.com.txt", "webhook_url":"https://your-webhook-endpoint.com/callback"}' \
  http://localhost:9000/scan-url-async
```

### Scan a Local File (Container Disk)

If you have mounted a volume into the container, you can instruct ClamAV to scan a file already residing locally on the container's disk.

```bash
curl -i "http://localhost:9000/scanPath?path=/tmp/suspicious_file.txt"
```

## Admin API

To allow cluster administrators to manage the running ClamAV daemon, we provide a set of administrative endpoints. 

> **Important Security Note:** The Admin API is **disabled by default**. To enable it, you must start the container with the `ADMIN_API_KEY` environment variable. This key must then be provided via the `X-API-Key` or `Authorization` header for all `/admin/*` endpoints.

### 1. Get Daemon Status
Returns the current ClamAV engine version and internal memory statistics.
```bash
curl -H "X-API-Key: your-admin-key" http://localhost:9000/admin/status
```

### 2. Reload Virus Database
Forces the ClamAV daemon to reload its virus database from disk into memory without restarting the container.
```bash
curl -X POST -H "X-API-Key: your-admin-key" http://localhost:9000/admin/reload
```

### 3. Update Signatures
Forces `freshclam` to execute immediately in the background, downloading the absolute latest virus definitions from the internet.
```bash
curl -X POST -H "X-API-Key: your-admin-key" http://localhost:9000/admin/update-signatures
```

## API Routes Reference

Below is a complete reference of all available HTTP endpoints exposed by the service.

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/scan` | Scans a file uploaded via `multipart/form-data` (`file` field). | `API_KEY` (if set) |
| `GET`  | `/scanPath` | Scans a local file already residing on the container's disk (`?path=/tmp/file`). | `API_KEY` (if set) |
| `POST` | `/scan-url` | Scans a file by streaming it from a remote URL. Payload: `{"url":"..."}`. | `API_KEY` (if set) |
| `POST` | `/scan-async` | Asynchronously scans an uploaded file. Requires `file` and `webhook_url` form fields. | `API_KEY` (if set) |
| `POST` | `/scan-url-async` | Asynchronously scans a URL. Payload: `{"url":"...", "webhook_url":"..."}`. | `API_KEY` (if set) |
| `GET`  | `/admin/status` | Returns ClamAV engine version and internal memory stats. | `ADMIN_API_KEY` |
| `POST` | `/admin/reload` | Forces ClamAV to hot-reload virus databases from disk to memory. | `ADMIN_API_KEY` |
| `POST` | `/admin/update-signatures` | Forces `freshclam` to update virus signatures immediately in the background. | `ADMIN_API_KEY` |

## Status Codes

The API strictly adheres to the following status codes for all scan endpoints and webhook payloads:
- `200` - Clean file (no known infections)
- `400` - ClamAV returned a general error for the file
- `406` - INFECTED
- `412` - Unable to parse the file
- `501` - Unknown request

## Authentication

By default, the API is completely open. If you wish to secure your endpoints, start the container with the `API_KEY` environment variable.

```bash
docker run -d -p 9000:9000 -e API_KEY=your-secret-key --name clamav-restapi amithalder/clamav-restapi:latest
```

Clients must then provide the key via the `X-API-Key` or `Authorization` header:
```bash
curl -H "X-API-Key: your-secret-key" -F "file=@eicar.com.txt" http://localhost:9000/scan
```

## Configuration

### Environment Variables

Below is the complete list of available options that can be used to customize your installation.

| Parameter | Description |
|-----------|-------------|
| `API_KEY` | Secures the REST API with a required API key. |
| `ADMIN_API_KEY` | Enables and secures the `/admin/*` REST endpoints. |
| `CLAMD_PORT` | The internal connection string used to talk to the ClamAV daemon - Default `tcp://localhost:3310` |
| `MAX_SCAN_SIZE` | Amount of data scanned for each file - Default `100M` |
| `MAX_FILE_SIZE` | Don't scan files larger than this size - Default `25M` |
| `MAX_RECURSION` | How many nested archives to scan - Default `16` |
| `MAX_FILES` | Number of files to scan within an archive - Default `10000` |
| `MAX_EMBEDDEDPE` | Maximum file size for embedded PE - Default `10M` |
| `MAX_HTMLNORMALIZE` | Maximum size of HTML to normalize - Default `10M` |
| `MAX_HTMLNOTAGS` | Maximum size of Normalized HTML File to scan - Default `2M` |
| `MAX_SCRIPTNORMALIZE` | Maximum size of a Script to normalize - Default `5M` |
| `MAX_ZIPTYPERCG` | Maximum size of ZIP to reanalyze type recognition - Default `1M` |
| `MAX_PARTITIONS` | How many partitions per Raw disk to scan - Default `50` |
| `MAX_ICONSPE` | How many Icons in PE to scan - Default `100` |
| `PCRE_MATCHLIMIT` | Maximum PCRE Match Calls - Default `100000` |
| `PCRE_RECMATCHLIMIT` | Maximum Recursive Match Calls to PCRE - Default `2000` |
| `SIGNATURE_CHECKS` | Check times per day for a new database signature. Must be between 1 and 50. - Default `24` |

### Networking

| Port | Description |
|-----------|-------------|
| `9000`    | HTTP REST API Port |
| `9443`    | HTTPS REST API Port |
| `3310`    | Internal ClamD Listening Port |

## Maintenance & Monitoring

### Shell Access

For debugging and maintenance purposes, you may access the container shell:
```bash
docker exec -it clamav-restapi /bin/sh
```

### Enabling HTTPS (TLS)

The REST API natively listens for HTTPS traffic on port `9443`. To enable this securely, you must mount your SSL certificate and key directly into the container at runtime:

```bash
docker run -d \
  -p 9443:9443 \
  -v /path/to/your/cert.crt:/etc/ssl/clamav-rest/server.crt \
  -v /path/to/your/cert.key:/etc/ssl/clamav-rest/server.key \
  amithalder/clamav-restapi:alpine-latest
```

## Developing

To build the project locally (requires Go 1.23+):
```bash
go mod tidy
go build -v .
```

To test the locally built Docker image:
```bash
docker build -t amithalder/clamav-restapi:alpine-latest .
docker run -p 9000:9000 -p 9443:9443 -itd --name clamav-restapi amithalder/clamav-restapi:alpine-latest
```

## References
- https://www.clamav.net
