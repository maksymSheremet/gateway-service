# Gateway Service

## Overview

Spring Cloud Gateway acts as the single entry point for all platform microservices.
Runs on a **reactive stack** (WebFlux + Netty), routes requests to downstream services,
validates JWT tokens, and propagates user context via HTTP headers.

## Features

- **Single Entry Point** — clients access one port (8085) instead of multiple service ports
- **JWT Validation** — signature, issuer, and token type verification at the gateway level
- **Header Propagation** — `X-User-Id`, `X-User-Email`, `X-User-Role` propagated to downstream services
- **Defense in Depth** — gateway validates JWT, downstream services validate independently (Variant B)
- **CORS** — centralized configuration for frontend origins
- **Health Checks** — Spring Actuator with gateway routes endpoint

## Tech Stack

- **Java** 25
- **Gradle** 9.1.0
- **Spring Boot** 3.5.11
- **Spring Cloud** 2025.0.0 (`spring-cloud-starter-gateway-server-webflux`)
- **Reactor Netty** — non-blocking HTTP server (not Tomcat)
- **jjwt** 0.12.6 — JWT parsing and validation

## Project Structure

```
my.code.gateway
├── config/
│   ├── JwtProperties.java       — record, binds jwt.secret from application.yml
│   └── SecurityConfig.java      — WebFlux security (permitAll + disable CSRF)
├── filter/
│   └── JwtValidationFilter.java — GlobalFilter, JWT validation + header propagation
└── GatewayServiceApplication.java
```

## Routing

| Path Pattern   | Destination          | Auth Required |
|----------------|----------------------|---------------|
| `/api/auth/**` | auth-service (8080)  | No*           |
| `/api/me/**`   | user-service (8081)  | Yes           |

\* Public endpoints: `/api/auth/register`, `/api/auth/authenticate`, `/api/auth/refresh`, `/api/auth/logout`

> Internal endpoints (`/api/internal/**`) are **not** routed through gateway — service-to-service calls go directly, secured via `X-Internal-Api-Key`.

## JWT Validation Flow

```
Client → Gateway:8085
  │
  ├─ Public path? → pass through (no JWT check)
  │
  ├─ No Authorization header? → 401
  │
  ├─ Parse JWT:
  │   ├─ Verify signature (HMAC, same Base64-decoded key as auth-service)
  │   ├─ Verify issuer = "auth-service"
  │   ├─ Verify tokenType = "ACCESS" (reject REFRESH tokens)
  │   └─ Check expiration
  │
  ├─ Extract claims → add headers:
  │   ├─ X-User-Id: "42"
  │   ├─ X-User-Email: "user@example.com"
  │   └─ X-User-Role: "ROLE_USER"
  │
  └─ Proxy request to downstream service
```

## Configuration

### Property Prefix (Spring Cloud 2025.0.0)

Routes and CORS use the new prefix: `spring.cloud.gateway.server.webflux.*`
The old prefix `spring.cloud.gateway.*` is deprecated and will be removed in the next major version.

### Actuator Endpoint Access (Spring Boot 3.5.x)

Gateway routes endpoint uses `management.endpoint.gateway.access: unrestricted`
The old `management.endpoint.gateway.enabled: true` is no longer supported.

### Environment Variables

| Variable             | Description                            | Required |
|----------------------|----------------------------------------|----------|
| `YOUR_JWT_SECRET_KEY`| Base64-encoded HMAC key (same as auth) | Yes      |

### Actuator Endpoints

| Path                       | Description       |
|----------------------------|-------------------|
| `/actuator/health`         | Health check      |
| `/actuator/info`           | App info          |
| `/actuator/gateway/routes` | Registered routes |

## Tests

| Test Class                | Type | Tests | Coverage                                        |
|---------------------------|------|-------|-------------------------------------------------|
| `JwtValidationFilterTest` | Unit | 10    | Public paths, auth headers, valid/invalid tokens |

## Setup

### Prerequisites
- Java 25
- auth-service (8080) and user-service (8081) running

### Run locally

```bash
# Start gateway
./gradlew bootRun

# Or with env variable
YOUR_JWT_SECRET_KEY=<base64-key> ./gradlew bootRun
```

### Run tests

```bash
./gradlew test
```

### Verify

```bash
# Authenticate through gateway
curl -X POST http://localhost:8085/api/auth/authenticate \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"MyPass123!"}'

# Use token for protected endpoint
curl http://localhost:8085/api/me \
  -H "Authorization: Bearer <access_token>"

# Check registered routes
curl http://localhost:8085/actuator/gateway/routes
```

## Key Design Decisions

**Why WebFlux (not Servlet)?**
Gateway is I/O-bound — it proxies requests, not computes. Reactive non-blocking model handles more concurrent connections with fewer threads than thread-per-request Servlet model.

**Why GlobalFilter (not GatewayFilter)?**
GlobalFilter applies to all routes automatically. Per-route GatewayFilter risks forgetting JWT validation when adding new routes.

**Why gateway validates JWT + downstream also validates?**
Defense in depth. If someone bypasses gateway (misconfigured network, direct service access), downstream services are still protected.

**Why Base64.decode() for JWT secret?**
The secret is generated via `openssl rand -base64 36`. All services must decode it the same way — `Decoders.BASE64.decode()`, not `getBytes(UTF_8)`. Mismatch causes silent signature failures.
