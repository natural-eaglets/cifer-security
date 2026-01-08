# CIFER Security — API Specification

> **Document Version:** 0.2  
> **Last Updated:** 2026-01-08  
> **Classification:** Technical Specification  
> **Target Audience:** Developers, Integration Engineers, Enterprise Architects

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [API Overview](#2-api-overview)
3. [Authentication](#3-authentication)
4. [REST API Reference](#4-rest-api-reference)
5. [gRPC API Reference](#5-grpc-api-reference)
6. [SDK Design](#6-sdk-design)
7. [Webhooks](#7-webhooks)
8. [Rate Limiting](#8-rate-limiting)
9. [Error Handling](#9-error-handling)
10. [Integration Patterns](#10-integration-patterns)
11. [Migration Guide](#11-migration-guide)
12. [References](#12-references)

---

## 1. Introduction

### 1.1 Purpose

This document specifies the public API for CIFER Security's zero-key encryption platform. It provides complete reference documentation for integrating CIFER encryption into applications.

### 1.2 API Design Principles

| Principle | Implementation |
|-----------|----------------|
| **RESTful** | Resource-oriented URLs, standard HTTP methods |
| **Consistent** | Uniform response format, predictable behavior |
| **Secure** | TLS-only, authentication required |
| **Versioned** | URL versioning (/v1/), backward compatible |
| **Idempotent** | Safe retry for network failures |

### 1.3 Base URLs

| Environment | Base URL |
|-------------|----------|
| Production | `https://api.cifer.io/v1` |
| Staging | `https://api.staging.cifer.io/v1` |
| Development | `https://api.dev.cifer.io/v1` |

---

## 2. API Overview

### 2.1 Resource Hierarchy

```
/v1
├── /cifers                      # CIFER management
│   ├── POST /                   # Create CIFER
│   ├── GET /{cifer_id}          # Get CIFER details
│   ├── DELETE /{cifer_id}       # Revoke CIFER
│   └── POST /{cifer_id}/rotate  # Rotate key
│
├── /encrypt                     # Encryption operations
│   └── POST /                   # Encrypt data
│
├── /decrypt                     # Decryption operations
│   └── POST /                   # Decrypt data
│
├── /keys                        # Public key retrieval
│   └── GET /{cifer_id}          # Get encryption key
│
└── /health                      # Service health
    └── GET /                    # Health check
```

### 2.2 Common Headers

**Request Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | Bearer token or API key |
| `Content-Type` | Yes | `application/json` or `application/octet-stream` |
| `X-Request-ID` | No | Client-generated request ID for tracing |
| `X-Idempotency-Key` | No | For idempotent POST requests |

**Response Headers:**

| Header | Description |
|--------|-------------|
| `X-Request-ID` | Server-assigned or echoed request ID |
| `X-RateLimit-Limit` | Rate limit ceiling |
| `X-RateLimit-Remaining` | Remaining requests in window |
| `X-RateLimit-Reset` | Unix timestamp when limit resets |

### 2.3 Response Format

All responses follow a consistent envelope:

```json
{
    "success": true,
    "data": { ... },
    "meta": {
        "request_id": "req_abc123",
        "timestamp": "2026-01-08T10:30:00Z",
        "version": "1.0"
    }
}
```

Error responses:

```json
{
    "success": false,
    "error": {
        "code": "INVALID_CIFER_ID",
        "message": "The specified CIFER does not exist",
        "details": {
            "cifer_id": "cif_invalid123"
        }
    },
    "meta": {
        "request_id": "req_abc123",
        "timestamp": "2026-01-08T10:30:00Z"
    }
}
```

---

## 3. Authentication

### 3.1 Authentication Methods

| Method | Use Case | Security Level |
|--------|----------|----------------|
| **API Key** | Server-to-server | High |
| **OAuth 2.0** | User-facing apps | High |
| **JWT** | Stateless sessions | High |

### 3.2 API Key Authentication

```http
GET /v1/cifers/cif_abc123 HTTP/1.1
Host: api.cifer.io
Authorization: Bearer sk_live_abc123def456...
```

API Key format:
- Test keys: `sk_test_` prefix
- Live keys: `sk_live_` prefix
- 64 characters total

### 3.3 OAuth 2.0 Flow

```mermaid
sequenceDiagram
    participant User
    participant App
    participant CiferAuth as CIFER Auth Server
    participant CiferAPI as CIFER API
    
    User->>App: Login
    App->>CiferAuth: GET /oauth/authorize
    CiferAuth->>User: Login prompt
    User->>CiferAuth: Credentials
    CiferAuth->>App: Authorization code
    App->>CiferAuth: POST /oauth/token (code)
    CiferAuth->>App: Access token + Refresh token
    App->>CiferAPI: API request + Access token
    CiferAPI->>App: Response
```

**Token endpoint:**

```http
POST /oauth/token HTTP/1.1
Host: auth.cifer.io
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=auth_code_here
&redirect_uri=https://yourapp.com/callback
&client_id=your_client_id
&client_secret=your_client_secret
```

### 3.4 Scopes

| Scope | Description |
|-------|-------------|
| `cifer:read` | Read CIFER metadata |
| `cifer:create` | Create new CIFERs |
| `cifer:delete` | Revoke CIFERs |
| `encrypt` | Encrypt data |
| `decrypt` | Decrypt data |
| `admin` | Administrative operations |

---

## 4. REST API Reference

### 4.1 Create CIFER

Creates a new CIFER encryption identity.

**Endpoint:** `POST /v1/cifers`

**Request:**

```http
POST /v1/cifers HTTP/1.1
Host: api.cifer.io
Authorization: Bearer sk_live_abc123...
Content-Type: application/json
X-Idempotency-Key: idem_xyz789

{
    "name": "my-encryption-key",
    "description": "Production encryption key for user data",
    "metadata": {
        "environment": "production",
        "team": "backend"
    },
    "policy": {
        "auto_rotate_days": 90,
        "allowed_operations": ["encrypt", "decrypt"]
    }
}
```

**Response (201 Created):**

```json
{
    "success": true,
    "data": {
        "cifer_id": "cif_abc123def456",
        "name": "my-encryption-key",
        "description": "Production encryption key for user data",
        "status": "active",
        "created_at": "2026-01-08T10:30:00Z",
        "owner_id": "usr_owner123",
        "encapsulation_key": "MIIBoj...",
        "key_version": 1,
        "metadata": {
            "environment": "production",
            "team": "backend"
        },
        "policy": {
            "auto_rotate_days": 90,
            "allowed_operations": ["encrypt", "decrypt"]
        }
    },
    "meta": {
        "request_id": "req_abc123",
        "timestamp": "2026-01-08T10:30:00Z"
    }
}
```

**OpenAPI Schema:**

```yaml
openapi: 3.1.0
paths:
  /v1/cifers:
    post:
      operationId: createCifer
      summary: Create a new CIFER
      tags:
        - CIFERs
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateCiferRequest'
      responses:
        '201':
          description: CIFER created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CiferResponse'
        '400':
          $ref: '#/components/responses/BadRequest'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '429':
          $ref: '#/components/responses/RateLimited'

components:
  schemas:
    CreateCiferRequest:
      type: object
      properties:
        name:
          type: string
          maxLength: 255
          description: Human-readable name
        description:
          type: string
          maxLength: 1000
        metadata:
          type: object
          additionalProperties:
            type: string
        policy:
          $ref: '#/components/schemas/CiferPolicy'
          
    CiferPolicy:
      type: object
      properties:
        auto_rotate_days:
          type: integer
          minimum: 0
          maximum: 365
        allowed_operations:
          type: array
          items:
            type: string
            enum: [encrypt, decrypt, rotate, revoke]
```

---

### 4.2 Get CIFER

Retrieves details about a CIFER.

**Endpoint:** `GET /v1/cifers/{cifer_id}`

**Response (200 OK):**

```json
{
    "success": true,
    "data": {
        "cifer_id": "cif_abc123def456",
        "name": "my-encryption-key",
        "status": "active",
        "created_at": "2026-01-08T10:30:00Z",
        "updated_at": "2026-01-08T10:30:00Z",
        "owner_id": "usr_owner123",
        "key_version": 1,
        "key_algorithm": "ML-KEM-768",
        "statistics": {
            "total_encryptions": 1523,
            "total_decryptions": 892,
            "last_used_at": "2026-01-08T09:15:00Z"
        }
    }
}
```

---

### 4.3 Encrypt Data

Encrypts data for a CIFER recipient.

**Endpoint:** `POST /v1/encrypt`

**Request (JSON):**

```http
POST /v1/encrypt HTTP/1.1
Host: api.cifer.io
Authorization: Bearer sk_live_abc123...
Content-Type: application/json

{
    "cifer_id": "cif_abc123def456",
    "plaintext": "SGVsbG8gV29ybGQh",
    "encoding": "base64",
    "metadata": {
        "filename": "secret.txt",
        "content_type": "text/plain"
    }
}
```

**Request (Binary):**

```http
POST /v1/encrypt HTTP/1.1
Host: api.cifer.io
Authorization: Bearer sk_live_abc123...
Content-Type: application/octet-stream
X-Cifer-Id: cif_abc123def456
X-Cifer-Metadata: {"filename": "secret.bin"}

<binary data>
```

**Response (200 OK):**

```json
{
    "success": true,
    "data": {
        "ciphertext": "Q0lGUgABAA...",
        "encoding": "base64",
        "envelope_size": 1234,
        "algorithm": {
            "kem": "ML-KEM-768",
            "aead": "AES-256-GCM"
        },
        "metadata": {
            "filename": "secret.txt",
            "content_type": "text/plain"
        }
    }
}
```

**OpenAPI Schema:**

```yaml
paths:
  /v1/encrypt:
    post:
      operationId: encryptData
      summary: Encrypt data for a CIFER
      tags:
        - Encryption
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/EncryptRequest'
          application/octet-stream:
            schema:
              type: string
              format: binary
      responses:
        '200':
          description: Data encrypted successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/EncryptResponse'
            application/octet-stream:
              schema:
                type: string
                format: binary

components:
  schemas:
    EncryptRequest:
      type: object
      required:
        - cifer_id
        - plaintext
      properties:
        cifer_id:
          type: string
          pattern: '^cif_[a-zA-Z0-9]{12,}$'
        plaintext:
          type: string
          description: Base64-encoded plaintext
        encoding:
          type: string
          enum: [base64, hex]
          default: base64
        metadata:
          type: object
          additionalProperties:
            type: string
            
    EncryptResponse:
      type: object
      properties:
        ciphertext:
          type: string
          description: Base64-encoded ciphertext envelope
        encoding:
          type: string
        envelope_size:
          type: integer
        algorithm:
          type: object
          properties:
            kem:
              type: string
            aead:
              type: string
```

---

### 4.4 Decrypt Data

Decrypts data owned by the authenticated user.

**Endpoint:** `POST /v1/decrypt`

**Request:**

```http
POST /v1/decrypt HTTP/1.1
Host: api.cifer.io
Authorization: Bearer sk_live_abc123...
Content-Type: application/json

{
    "ciphertext": "Q0lGUgABAA...",
    "encoding": "base64"
}
```

**Response (200 OK):**

```json
{
    "success": true,
    "data": {
        "plaintext": "SGVsbG8gV29ybGQh",
        "encoding": "base64",
        "cifer_id": "cif_abc123def456",
        "key_version": 1,
        "metadata": {
            "filename": "secret.txt",
            "content_type": "text/plain"
        }
    }
}
```

**Error Response (403 Forbidden):**

```json
{
    "success": false,
    "error": {
        "code": "UNAUTHORIZED_DECRYPT",
        "message": "You are not authorized to decrypt this ciphertext",
        "details": {
            "cifer_id": "cif_abc123def456",
            "owner_id": "usr_different_owner"
        }
    }
}
```

---

### 4.5 Rotate Key

Rotates the encryption key for a CIFER.

**Endpoint:** `POST /v1/cifers/{cifer_id}/rotate`

**Request:**

```http
POST /v1/cifers/cif_abc123/rotate HTTP/1.1
Host: api.cifer.io
Authorization: Bearer sk_live_abc123...
Content-Type: application/json

{
    "reason": "scheduled_rotation",
    "re_encryption_window_days": 30
}
```

**Response (200 OK):**

```json
{
    "success": true,
    "data": {
        "cifer_id": "cif_abc123def456",
        "old_key_version": 1,
        "new_key_version": 2,
        "new_encapsulation_key": "MIIBpj...",
        "rotation_initiated_at": "2026-01-08T10:30:00Z",
        "re_encryption_deadline": "2026-02-07T10:30:00Z"
    }
}
```

---

### 4.6 Revoke CIFER

Permanently revokes a CIFER (irreversible).

**Endpoint:** `DELETE /v1/cifers/{cifer_id}`

**Request:**

```http
DELETE /v1/cifers/cif_abc123 HTTP/1.1
Host: api.cifer.io
Authorization: Bearer sk_live_abc123...
X-Confirm-Revocation: true
```

**Response (200 OK):**

```json
{
    "success": true,
    "data": {
        "cifer_id": "cif_abc123def456",
        "status": "revoked",
        "revoked_at": "2026-01-08T10:30:00Z",
        "warning": "This action is irreversible. All encrypted data will become permanently inaccessible."
    }
}
```

---

### 4.7 Get Public Key

Retrieves the public encryption key for a CIFER (no authentication required for encrypt-to-others).

**Endpoint:** `GET /v1/keys/{cifer_id}`

**Response (200 OK):**

```json
{
    "success": true,
    "data": {
        "cifer_id": "cif_abc123def456",
        "encapsulation_key": "MIIBoj...",
        "key_version": 1,
        "algorithm": "ML-KEM-768",
        "valid_until": "2026-04-08T10:30:00Z"
    }
}
```

---

## 5. gRPC API Reference

### 5.1 Service Definition

```protobuf
syntax = "proto3";

package cifer.v1;

import "google/protobuf/timestamp.proto";

service CiferService {
    // CIFER Management
    rpc CreateCifer(CreateCiferRequest) returns (CiferResponse);
    rpc GetCifer(GetCiferRequest) returns (CiferResponse);
    rpc ListCifers(ListCifersRequest) returns (ListCifersResponse);
    rpc RotateKey(RotateKeyRequest) returns (RotateKeyResponse);
    rpc RevokeCifer(RevokeCiferRequest) returns (RevokeCiferResponse);
    
    // Encryption Operations
    rpc Encrypt(EncryptRequest) returns (EncryptResponse);
    rpc EncryptStream(stream EncryptStreamRequest) returns (stream EncryptStreamResponse);
    rpc Decrypt(DecryptRequest) returns (DecryptResponse);
    rpc DecryptStream(stream DecryptStreamRequest) returns (stream DecryptStreamResponse);
    
    // Key Retrieval
    rpc GetPublicKey(GetPublicKeyRequest) returns (GetPublicKeyResponse);
}

// Messages
message CreateCiferRequest {
    string name = 1;
    string description = 2;
    map<string, string> metadata = 3;
    CiferPolicy policy = 4;
}

message CiferResponse {
    string cifer_id = 1;
    string name = 2;
    string description = 3;
    CiferStatus status = 4;
    google.protobuf.Timestamp created_at = 5;
    google.protobuf.Timestamp updated_at = 6;
    string owner_id = 7;
    bytes encapsulation_key = 8;
    int32 key_version = 9;
    map<string, string> metadata = 10;
    CiferPolicy policy = 11;
}

message EncryptRequest {
    string cifer_id = 1;
    bytes plaintext = 2;
    map<string, string> metadata = 3;
}

message EncryptResponse {
    bytes ciphertext = 1;
    int32 envelope_size = 2;
    Algorithm algorithm = 3;
}

message DecryptRequest {
    bytes ciphertext = 1;
}

message DecryptResponse {
    bytes plaintext = 1;
    string cifer_id = 2;
    int32 key_version = 3;
    map<string, string> metadata = 4;
}

// Streaming for large files
message EncryptStreamRequest {
    oneof data {
        EncryptStreamInit init = 1;
        bytes chunk = 2;
    }
}

message EncryptStreamInit {
    string cifer_id = 1;
    int64 total_size = 2;
    map<string, string> metadata = 3;
}

message EncryptStreamResponse {
    oneof data {
        EncryptStreamHeader header = 1;
        bytes chunk = 2;
        EncryptStreamComplete complete = 3;
    }
}

message EncryptStreamHeader {
    int64 total_size = 1;
    Algorithm algorithm = 2;
}

message EncryptStreamComplete {
    bytes checksum = 1;
}

// Enums
enum CiferStatus {
    CIFER_STATUS_UNSPECIFIED = 0;
    CIFER_STATUS_PENDING = 1;
    CIFER_STATUS_ACTIVE = 2;
    CIFER_STATUS_ROTATING = 3;
    CIFER_STATUS_REVOKED = 4;
}

message Algorithm {
    string kem = 1;
    string aead = 2;
}

message CiferPolicy {
    int32 auto_rotate_days = 1;
    repeated string allowed_operations = 2;
}
```

### 5.2 gRPC Client Example

```go
package main

import (
    "context"
    "log"
    
    pb "github.com/cifer-io/sdk-go/proto/v1"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

func main() {
    // Connect to CIFER API
    creds, _ := credentials.NewClientTLSFromFile("ca.pem", "api.cifer.io")
    conn, err := grpc.Dial("api.cifer.io:443", grpc.WithTransportCredentials(creds))
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    client := pb.NewCiferServiceClient(conn)
    
    // Create CIFER
    resp, err := client.CreateCifer(context.Background(), &pb.CreateCiferRequest{
        Name: "my-key",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Created CIFER: %s", resp.CiferId)
    
    // Encrypt data
    encResp, err := client.Encrypt(context.Background(), &pb.EncryptRequest{
        CiferId:   resp.CiferId,
        Plaintext: []byte("Hello, World!"),
    })
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Encrypted %d bytes", encResp.EnvelopeSize)
}
```

---

## 6. SDK Design

### 6.1 SDK Languages

| Language | Package | Status |
|----------|---------|--------|
| **Go** | `github.com/cifer-io/sdk-go` | Stable |
| **Rust** | `cifer-sdk` (crates.io) | Stable |
| **TypeScript/JS** | `@cifer-io/sdk` (npm) | Stable |
| **Python** | `cifer-sdk` (PyPI) | Stable |
| **Java** | `io.cifer:sdk` (Maven) | Beta |
| **C#** | `Cifer.Sdk` (NuGet) | Beta |

### 6.2 Go SDK

```go
package main

import (
    "context"
    "log"
    
    "github.com/cifer-io/sdk-go/cifer"
)

func main() {
    // Initialize client
    client, err := cifer.NewClient(
        cifer.WithAPIKey("sk_live_abc123..."),
        cifer.WithRegion("us-east"),
    )
    if err != nil {
        log.Fatal(err)
    }
    
    // Create CIFER
    cif, err := client.Cifers.Create(context.Background(), &cifer.CreateParams{
        Name: "my-encryption-key",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // Encrypt
    encrypted, err := client.Encrypt(context.Background(), cif.ID, []byte("secret data"))
    if err != nil {
        log.Fatal(err)
    }
    
    // Decrypt
    decrypted, err := client.Decrypt(context.Background(), encrypted)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Decrypted: %s", string(decrypted.Plaintext))
}
```

### 6.3 TypeScript SDK

```typescript
import { CiferClient } from '@cifer-io/sdk';

async function main() {
    // Initialize client
    const cifer = new CiferClient({
        apiKey: 'sk_live_abc123...',
        region: 'us-east',
    });
    
    // Create CIFER
    const myCifer = await cifer.cifers.create({
        name: 'my-encryption-key',
    });
    
    // Encrypt
    const encrypted = await cifer.encrypt(myCifer.id, Buffer.from('secret data'));
    
    // Decrypt
    const decrypted = await cifer.decrypt(encrypted.ciphertext);
    
    console.log('Decrypted:', decrypted.plaintext.toString());
}

main().catch(console.error);
```

### 6.4 Python SDK

```python
from cifer import CiferClient

# Initialize client
client = CiferClient(api_key="sk_live_abc123...")

# Create CIFER
my_cifer = client.cifers.create(name="my-encryption-key")

# Encrypt
encrypted = client.encrypt(my_cifer.id, b"secret data")

# Decrypt
decrypted = client.decrypt(encrypted.ciphertext)

print(f"Decrypted: {decrypted.plaintext.decode()}")
```

### 6.5 Rust SDK

```rust
use cifer_sdk::{CiferClient, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize client
    let client = CiferClient::new("sk_live_abc123...")?;
    
    // Create CIFER
    let my_cifer = client.cifers()
        .create()
        .name("my-encryption-key")
        .send()
        .await?;
    
    // Encrypt
    let encrypted = client.encrypt(&my_cifer.id, b"secret data").await?;
    
    // Decrypt
    let decrypted = client.decrypt(&encrypted.ciphertext).await?;
    
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted.plaintext));
    
    Ok(())
}
```

### 6.6 SDK Features Matrix

| Feature | Go | Rust | TS | Python | Java |
|---------|-----|------|-----|--------|------|
| Sync API | - | - | - | ✓ | ✓ |
| Async API | ✓ | ✓ | ✓ | ✓ | ✓ |
| Streaming | ✓ | ✓ | ✓ | ✓ | ✓ |
| Auto-retry | ✓ | ✓ | ✓ | ✓ | ✓ |
| Circuit breaker | ✓ | ✓ | ✓ | ✓ | ✓ |
| Connection pool | ✓ | ✓ | ✓ | ✓ | ✓ |
| Metrics | ✓ | ✓ | ✓ | ✓ | ✓ |
| Tracing | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## 7. Webhooks

### 7.1 Webhook Events

| Event | Description |
|-------|-------------|
| `cifer.created` | New CIFER created |
| `cifer.rotated` | Key rotation completed |
| `cifer.revoked` | CIFER revoked |
| `cifer.expiring` | CIFER key expiring soon |
| `decrypt.failed` | Decrypt attempt failed |
| `quota.exceeded` | Usage quota exceeded |

### 7.2 Webhook Payload

```json
{
    "id": "evt_abc123",
    "type": "cifer.created",
    "created": "2026-01-08T10:30:00Z",
    "data": {
        "cifer_id": "cif_abc123def456",
        "name": "my-encryption-key",
        "owner_id": "usr_owner123"
    }
}
```

### 7.3 Webhook Signature Verification

```python
import hmac
import hashlib

def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    """Verify webhook signature."""
    expected = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(f"sha256={expected}", signature)

# Usage
is_valid = verify_webhook(
    request.body,
    request.headers['X-Cifer-Signature'],
    webhook_secret
)
```

### 7.4 Webhook Configuration

**Create webhook endpoint:**

```http
POST /v1/webhooks HTTP/1.1
Host: api.cifer.io
Authorization: Bearer sk_live_abc123...
Content-Type: application/json

{
    "url": "https://yourapp.com/webhooks/cifer",
    "events": ["cifer.created", "cifer.rotated", "cifer.revoked"],
    "secret": "whsec_abc123..."
}
```

---

## 8. Rate Limiting

### 8.1 Rate Limits

| Endpoint Category | Limit | Window |
|-------------------|-------|--------|
| Create CIFER | 10 | 1 hour |
| Encrypt | 1000 | 1 minute |
| Decrypt | 100 | 1 minute |
| Get CIFER | 1000 | 1 minute |
| Key Rotation | 10 | 1 day |

### 8.2 Rate Limit Headers

```http
HTTP/1.1 200 OK
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1704711600
```

### 8.3 Rate Limit Exceeded Response

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 30
Content-Type: application/json

{
    "success": false,
    "error": {
        "code": "RATE_LIMIT_EXCEEDED",
        "message": "Rate limit exceeded. Please retry after 30 seconds.",
        "details": {
            "limit": 100,
            "window": "1 minute",
            "retry_after": 30
        }
    }
}
```

### 8.4 Rate Limit Best Practices

```typescript
import { CiferClient, RateLimitError } from '@cifer-io/sdk';

const cifer = new CiferClient({
    apiKey: 'sk_live_...',
    // Built-in rate limit handling
    rateLimitRetry: {
        maxRetries: 3,
        initialDelay: 1000,
        maxDelay: 30000,
    },
});

// Or handle manually
try {
    await cifer.encrypt(ciferId, data);
} catch (err) {
    if (err instanceof RateLimitError) {
        await sleep(err.retryAfter * 1000);
        // Retry
    }
}
```

---

## 9. Error Handling

### 9.1 Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_REQUEST` | 400 | Malformed request |
| `INVALID_CIFER_ID` | 400 | Invalid CIFER ID format |
| `INVALID_CIPHERTEXT` | 400 | Malformed ciphertext |
| `UNAUTHORIZED` | 401 | Invalid or missing credentials |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `UNAUTHORIZED_DECRYPT` | 403 | Not authorized to decrypt |
| `NOT_FOUND` | 404 | Resource not found |
| `CIFER_REVOKED` | 410 | CIFER has been revoked |
| `RATE_LIMIT_EXCEEDED` | 429 | Rate limit exceeded |
| `INTERNAL_ERROR` | 500 | Internal server error |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |

### 9.2 Error Response Format

```json
{
    "success": false,
    "error": {
        "code": "UNAUTHORIZED_DECRYPT",
        "message": "You are not authorized to decrypt this ciphertext",
        "details": {
            "cifer_id": "cif_abc123",
            "required_permission": "owner"
        },
        "documentation_url": "https://docs.cifer.io/errors/UNAUTHORIZED_DECRYPT"
    },
    "meta": {
        "request_id": "req_xyz789",
        "timestamp": "2026-01-08T10:30:00Z"
    }
}
```

### 9.3 SDK Error Handling

```typescript
import { 
    CiferClient, 
    CiferError,
    AuthenticationError,
    RateLimitError,
    NotFoundError,
    UnauthorizedDecryptError,
} from '@cifer-io/sdk';

try {
    const result = await cifer.decrypt(ciphertext);
} catch (err) {
    if (err instanceof AuthenticationError) {
        // Invalid API key
        console.error('Check your API key');
    } else if (err instanceof UnauthorizedDecryptError) {
        // Not the owner
        console.error(`CIFER ${err.ciferId} belongs to someone else`);
    } else if (err instanceof NotFoundError) {
        // CIFER doesn't exist
        console.error('CIFER not found');
    } else if (err instanceof RateLimitError) {
        // Rate limited
        console.error(`Retry after ${err.retryAfter} seconds`);
    } else if (err instanceof CiferError) {
        // Generic CIFER error
        console.error(`Error ${err.code}: ${err.message}`);
    } else {
        // Network or unexpected error
        throw err;
    }
}
```

---

## 10. Integration Patterns

### 10.1 Encryption at Rest

```typescript
// Database field encryption
class UserRepository {
    private cifer: CiferClient;
    private ciferId: string;
    
    async createUser(email: string, ssn: string) {
        // Encrypt sensitive fields
        const encryptedSsn = await this.cifer.encrypt(this.ciferId, Buffer.from(ssn));
        
        await db.insert('users', {
            email,
            ssn_encrypted: encryptedSsn.ciphertext,
        });
    }
    
    async getUserSsn(userId: string): Promise<string> {
        const user = await db.findById('users', userId);
        
        const decrypted = await this.cifer.decrypt(user.ssn_encrypted);
        return decrypted.plaintext.toString();
    }
}
```

### 10.2 File Encryption

```python
from cifer import CiferClient
import os

client = CiferClient(api_key=os.environ['CIFER_API_KEY'])

def encrypt_file(cifer_id: str, input_path: str, output_path: str):
    """Encrypt a file using streaming."""
    with open(input_path, 'rb') as f_in:
        with client.encrypt_stream(cifer_id, f_in) as encrypted:
            with open(output_path, 'wb') as f_out:
                for chunk in encrypted:
                    f_out.write(chunk)

def decrypt_file(input_path: str, output_path: str):
    """Decrypt a file using streaming."""
    with open(input_path, 'rb') as f_in:
        with client.decrypt_stream(f_in) as decrypted:
            with open(output_path, 'wb') as f_out:
                for chunk in decrypted:
                    f_out.write(chunk)
```

### 10.3 End-to-End Encryption

```typescript
// Messaging application
class SecureMessenger {
    private cifer: CiferClient;
    
    async sendMessage(recipientCiferId: string, message: string) {
        // Encrypt for recipient
        const encrypted = await this.cifer.encrypt(
            recipientCiferId,
            Buffer.from(message)
        );
        
        // Send encrypted message
        await api.sendMessage({
            ciphertext: encrypted.ciphertext,
        });
    }
    
    async receiveMessage(encryptedMessage: Buffer) {
        // Decrypt with own CIFER
        const decrypted = await this.cifer.decrypt(encryptedMessage);
        
        return decrypted.plaintext.toString();
    }
}
```

### 10.4 Sidecar Pattern (Kubernetes)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-cifer
spec:
  containers:
    - name: app
      image: myapp:latest
      env:
        - name: CIFER_PROXY_URL
          value: "http://localhost:8080"
    
    - name: cifer-sidecar
      image: cifer/proxy:latest
      ports:
        - containerPort: 8080
      env:
        - name: CIFER_API_KEY
          valueFrom:
            secretKeyRef:
              name: cifer-credentials
              key: api-key
```

---

## 11. Migration Guide

### 11.1 Migrating from AWS KMS

```python
# Before: AWS KMS
import boto3

kms = boto3.client('kms')

def encrypt_with_kms(key_id: str, plaintext: bytes) -> bytes:
    response = kms.encrypt(KeyId=key_id, Plaintext=plaintext)
    return response['CiphertextBlob']

# After: CIFER
from cifer import CiferClient

cifer = CiferClient(api_key="sk_live_...")

def encrypt_with_cifer(cifer_id: str, plaintext: bytes) -> bytes:
    response = cifer.encrypt(cifer_id, plaintext)
    return response.ciphertext

# Migration script
def migrate_encrypted_data(
    kms_key_id: str, 
    cifer_id: str,
    data_store
):
    for record in data_store.get_all():
        # Decrypt with KMS
        plaintext = kms.decrypt(
            CiphertextBlob=record.encrypted_data
        )['Plaintext']
        
        # Re-encrypt with CIFER
        new_ciphertext = cifer.encrypt(cifer_id, plaintext)
        
        # Update record
        record.encrypted_data = new_ciphertext.ciphertext
        data_store.update(record)
```

### 11.2 Migrating from HashiCorp Vault

```go
package main

import (
    vault "github.com/hashicorp/vault/api"
    "github.com/cifer-io/sdk-go/cifer"
)

func migrateFromVault(vaultClient *vault.Client, ciferClient *cifer.Client) error {
    // List Vault secrets
    secrets, err := vaultClient.Logical().List("secret/data")
    if err != nil {
        return err
    }
    
    for _, key := range secrets.Data["keys"].([]interface{}) {
        // Read from Vault
        secret, err := vaultClient.Logical().Read("secret/data/" + key.(string))
        if err != nil {
            return err
        }
        
        // Encrypt with CIFER
        for field, value := range secret.Data["data"].(map[string]interface{}) {
            encrypted, err := ciferClient.Encrypt(
                context.Background(),
                ciferId,
                []byte(value.(string)),
            )
            if err != nil {
                return err
            }
            
            // Store in new system
            newStore.Put(key.(string), field, encrypted.Ciphertext)
        }
    }
    
    return nil
}
```

### 11.3 Migration Checklist

```
Migration Checklist:

Pre-Migration:
[ ] Inventory all encrypted data locations
[ ] Create CIFER(s) for migration
[ ] Test encryption/decryption with sample data
[ ] Plan rollback procedure
[ ] Schedule maintenance window

Migration:
[ ] Run migration script
[ ] Verify migrated data can be decrypted
[ ] Update application configuration
[ ] Deploy updated application

Post-Migration:
[ ] Monitor for errors
[ ] Verify old system no longer in use
[ ] Decommission old encryption keys
[ ] Update documentation
```

---

## 12. References

### API Standards

1. **OpenAPI Specification 3.1** — https://spec.openapis.org/oas/v3.1.0
2. **gRPC Documentation** — https://grpc.io/docs/
3. **JSON:API Specification** — https://jsonapi.org/

### Security Standards

4. **OAuth 2.0** — RFC 6749
5. **JWT** — RFC 7519
6. **TLS 1.3** — RFC 8446

### SDK Best Practices

7. **Stripe API Design** — https://stripe.com/docs/api
8. **Twilio API Style Guide** — https://www.twilio.com/docs/usage/api

---

## Appendix A: OpenAPI Specification (Full)

```yaml
openapi: 3.1.0
info:
  title: CIFER Security API
  version: 1.0.0
  description: Zero-key encryption API
  contact:
    email: api@cifer.io
  license:
    name: Proprietary

servers:
  - url: https://api.cifer.io/v1
    description: Production
  - url: https://api.staging.cifer.io/v1
    description: Staging

security:
  - bearerAuth: []

paths:
  /cifers:
    post:
      operationId: createCifer
      summary: Create CIFER
      tags: [CIFERs]
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateCiferRequest'
      responses:
        '201':
          description: Created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CiferResponse'
    get:
      operationId: listCifers
      summary: List CIFERs
      tags: [CIFERs]
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
            default: 20
            maximum: 100
        - name: cursor
          in: query
          schema:
            type: string
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ListCifersResponse'

  /cifers/{cifer_id}:
    get:
      operationId: getCifer
      summary: Get CIFER
      tags: [CIFERs]
      parameters:
        - $ref: '#/components/parameters/CiferId'
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CiferResponse'
    delete:
      operationId: revokeCifer
      summary: Revoke CIFER
      tags: [CIFERs]
      parameters:
        - $ref: '#/components/parameters/CiferId'
      responses:
        '200':
          description: OK

  /cifers/{cifer_id}/rotate:
    post:
      operationId: rotateKey
      summary: Rotate key
      tags: [CIFERs]
      parameters:
        - $ref: '#/components/parameters/CiferId'
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RotateKeyRequest'
      responses:
        '200':
          description: OK

  /encrypt:
    post:
      operationId: encrypt
      summary: Encrypt data
      tags: [Encryption]
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/EncryptRequest'
          application/octet-stream:
            schema:
              type: string
              format: binary
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/EncryptResponse'

  /decrypt:
    post:
      operationId: decrypt
      summary: Decrypt data
      tags: [Encryption]
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/DecryptRequest'
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DecryptResponse'

  /keys/{cifer_id}:
    get:
      operationId: getPublicKey
      summary: Get public key
      tags: [Keys]
      security: []  # Public endpoint
      parameters:
        - $ref: '#/components/parameters/CiferId'
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/PublicKeyResponse'

  /health:
    get:
      operationId: healthCheck
      summary: Health check
      tags: [Health]
      security: []
      responses:
        '200':
          description: Healthy

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      
  parameters:
    CiferId:
      name: cifer_id
      in: path
      required: true
      schema:
        type: string
        pattern: '^cif_[a-zA-Z0-9]{12,}$'

  schemas:
    CreateCiferRequest:
      type: object
      properties:
        name:
          type: string
          maxLength: 255
        description:
          type: string
          maxLength: 1000
        metadata:
          type: object
          additionalProperties:
            type: string
        policy:
          $ref: '#/components/schemas/Policy'
          
    CiferResponse:
      type: object
      properties:
        success:
          type: boolean
        data:
          $ref: '#/components/schemas/Cifer'
        meta:
          $ref: '#/components/schemas/Meta'
          
    Cifer:
      type: object
      properties:
        cifer_id:
          type: string
        name:
          type: string
        description:
          type: string
        status:
          type: string
          enum: [pending, active, rotating, revoked]
        created_at:
          type: string
          format: date-time
        owner_id:
          type: string
        encapsulation_key:
          type: string
        key_version:
          type: integer
          
    EncryptRequest:
      type: object
      required: [cifer_id, plaintext]
      properties:
        cifer_id:
          type: string
        plaintext:
          type: string
        encoding:
          type: string
          enum: [base64, hex]
          default: base64
        metadata:
          type: object
          
    EncryptResponse:
      type: object
      properties:
        success:
          type: boolean
        data:
          type: object
          properties:
            ciphertext:
              type: string
            encoding:
              type: string
            envelope_size:
              type: integer
              
    DecryptRequest:
      type: object
      required: [ciphertext]
      properties:
        ciphertext:
          type: string
        encoding:
          type: string
          default: base64
          
    DecryptResponse:
      type: object
      properties:
        success:
          type: boolean
        data:
          type: object
          properties:
            plaintext:
              type: string
            cifer_id:
              type: string
            key_version:
              type: integer
              
    Policy:
      type: object
      properties:
        auto_rotate_days:
          type: integer
        allowed_operations:
          type: array
          items:
            type: string
            
    Meta:
      type: object
      properties:
        request_id:
          type: string
        timestamp:
          type: string
          format: date-time
          
    Error:
      type: object
      properties:
        success:
          type: boolean
          enum: [false]
        error:
          type: object
          properties:
            code:
              type: string
            message:
              type: string
            details:
              type: object

  responses:
    BadRequest:
      description: Bad Request
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
    Unauthorized:
      description: Unauthorized
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
    RateLimited:
      description: Rate Limited
      headers:
        Retry-After:
          schema:
            type: integer
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
```

---

## Appendix B: Postman Collection

Import this collection into Postman for API testing:

```json
{
    "info": {
        "name": "CIFER API",
        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
    },
    "auth": {
        "type": "bearer",
        "bearer": [
            {
                "key": "token",
                "value": "{{api_key}}",
                "type": "string"
            }
        ]
    },
    "variable": [
        {
            "key": "base_url",
            "value": "https://api.cifer.io/v1"
        },
        {
            "key": "api_key",
            "value": "sk_test_..."
        }
    ],
    "item": [
        {
            "name": "Create CIFER",
            "request": {
                "method": "POST",
                "url": "{{base_url}}/cifers",
                "body": {
                    "mode": "raw",
                    "raw": "{\"name\": \"test-key\"}",
                    "options": {
                        "raw": {
                            "language": "json"
                        }
                    }
                }
            }
        },
        {
            "name": "Encrypt",
            "request": {
                "method": "POST",
                "url": "{{base_url}}/encrypt",
                "body": {
                    "mode": "raw",
                    "raw": "{\"cifer_id\": \"{{cifer_id}}\", \"plaintext\": \"SGVsbG8gV29ybGQh\"}",
                    "options": {
                        "raw": {
                            "language": "json"
                        }
                    }
                }
            }
        },
        {
            "name": "Decrypt",
            "request": {
                "method": "POST",
                "url": "{{base_url}}/decrypt",
                "body": {
                    "mode": "raw",
                    "raw": "{\"ciphertext\": \"{{ciphertext}}\"}",
                    "options": {
                        "raw": {
                            "language": "json"
                        }
                    }
                }
            }
        }
    ]
}
```

