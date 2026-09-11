<img width="1070" alt="Authsignal" src="https://raw.githubusercontent.com/authsignal/authsignal-dotnet/main/.github/images/authsignal.png">

# Authsignal .NET SDK

The Authsignal .NET library for server-side applications.

## Installation

```
dotnet add package Authsignal.Server.Client
```

## Flows

```csharp
var flow = await client.StartFlow(new StartFlowRequest(
    "sign-in", User: new UserLookup(Email: "user@example.com"), ClientId: "your-client-id"));
await client.Email.Challenge(new EmailChallengeRequest(flow.ChallengeToken));
var verified = await client.Email.Verify(new OtpVerifyRequest(flow.ChallengeToken, verificationCode));
var result = await client.VerifyFlow(new VerifyFlowRequest("sign-in", verified.ChallengeToken));
```

The flow APIs are available on `IAuthsignalClient`. Use `client.Sms` with `SmsChallengeRequest` or `client.Whatsapp` with `WhatsappChallengeRequest` for phone OTPs. Challenge requests accept an optional `Email` or `PhoneNumber` for enrollment. An incorrect OTP throws `InvalidCodeException`, a subclass of `AuthsignalException`. All methods accept a `CancellationToken`.

`StartFlowRequest` also supports `Attributes` and `RedirectUrl`. Set one field in `UserLookup`: `UserId`, `Email`, `PhoneNumber`, or `Username`.

Follow `Action.NextStep` to choose the next challenge and repeat verification for any remaining steps. Always use the latest returned challenge token. Grant access only after final flow verification returns `CHALLENGE_SUCCEEDED`; `User` and `Session` are optional in the final response.

Start/verify flow use the configured API secret. OTP endpoints use `X-Authsignal-Challenge-Token` without Basic authentication and use the configured region URL.

## Documentation

Check out our [API documentation](https://docs.authsignal.com/sdks/server/overview) to see how to get up and running quickly.
