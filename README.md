<img width="1070" alt="Authsignal" src="https://raw.githubusercontent.com/authsignal/authsignal-dotnet/main/.github/images/authsignal.png">

# Authsignal .NET SDK

The Authsignal .NET library for server-side applications.

## Installation

```
dotnet add package Authsignal.Server.Client
```

## Retry policy

Requests use a 10-second timeout and retry twice by default with exponential backoff and jitter. Transient network failures, `429`, and `5xx` responses are retried for `GET`, `HEAD`, and `OPTIONS`; writes are retried only when they carry an idempotency key. Pass `retries: 0` to `AuthsignalClient` or `AddAuthsignal` to disable retries.

## Documentation

Check out our [API documentation](https://docs.authsignal.com/sdks/server/overview) to see how to get up and running quickly.
