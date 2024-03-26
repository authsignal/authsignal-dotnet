using System.Text.Json.Serialization;

namespace Authsignal;

public record class UserRequest(
    string UserId
);

public record class UserResponse(
    bool IsEnrolled
);

public record class TrackRequest(
    string UserId,
    string Action,
    string? Email = null,
    string? PhoneNumber = null,
    string? Username = null,
    string? IdempotencyKey = null,
    string? RedirectUrl = null,
    string? IpAddress = null,
    string? UserAgent = null,
    string? DeviceId = null,
    string? Scope = null,
    dynamic? Custom = null,
    bool? RedirectToSettings = false
);

public record class TrackRequestBody(
    string? Email = null,
    string? PhoneNumber = null,
    string? Username = null,
    string? IdempotencyKey = null,
    string? RedirectUrl = null,
    string? IpAddress = null,
    string? UserAgent = null,
    string? DeviceId = null,
    string? Scope = null,
    dynamic? Custom = null,
    bool? RedirectToSettings = false
);

public record class TrackResponse(
    UserActionState State,
    string IdempotencyKey,
    string Url,
    string Token,
    bool IsEnrolled
);

public record class ActionRequest(
    string UserId,
    string Action,
    string IdempotencyKey
);

public record class ActionResponse(
    UserActionState State
);

public record class ValidateChallengeRequest(
    string? UserId,
    string Token
);

public record class ValidateChallengeResponse(
    bool Success,
    UserActionState? State,
    string? UserId
);

public record class AuthenticatorRequest(
    string UserId,
    OobChannel OobChannel,
    string? PhoneNumber = null,
    string? Email = null
);

public record class AuthenticatorRequestBody(
    OobChannel OobChannel,
    string? PhoneNumber = null,
    string? Email = null
);

public record class AuthenticatorResponse(
    UserAuthenticator Authenticator,
    List<string> RecoveryCodes
);

public record class UserAuthenticator(
    string UserAuthenticatorId,
    AuthenticatorType AuthenticatorType,
    bool IsDefault,
    OobChannel? OobChannel,
    string CreatedAt,
    string? Email = null,
    string? PhoneNumber = null
);

public record class EmailRequest(
    string Email,
    string? RedirectUrl = null
);

public record class EmailRequestBody(
    string? RedirectUrl = null
);

public record class EmailResponse(
    string Url
);

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum UserActionState
{
    ALLOW,
    BLOCK,
    CHALLENGE_REQUIRED,
    CHALLENGE_SUCCEEDED,
    CHALLENGE_FAILED
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AuthenticatorType
{
    OOB,
    OTP
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum OobChannel
{
    SMS,
    EMAIL_MAGIC_LINK,
    EMAIL_OTP
}

public record class JwtOtherData(
    string IdempotencyKey,
    string ActionCode,
    string Username
);