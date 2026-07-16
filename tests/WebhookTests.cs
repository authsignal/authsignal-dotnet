using System.Security.Cryptography;
using System.Text;

namespace Authsignal.Tests;

public class WebhookTests : TestBase
{
    private string SignPayload(string payload, long timestamp)
    {
        var apiSecretKey = Configuration["ApiSecretKey"]!;

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(apiSecretKey));

        var hmacBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes($"{timestamp}.{payload}"));

        return $"t={timestamp},v2={Convert.ToBase64String(hmacBytes).TrimEnd('=')}";
    }

    [Fact]
    public void TestInvalidSignatureFormat()
    {
        string payload = "{}";
        string signature = "123";

        try
        {
            AuthsignalClient.Webhook.ConstructEvent(payload, signature);

            Assert.Fail("Expected an AuthsignalException to be thrown");
        }
        catch (Webhook.InvalidSignatureException ex)
        {
            Assert.Equal("Signature format is invalid.", ex.Message);
        }
    }

    [Fact]
    public void TestTimestampToleranceError()
    {
        string payload = "{}";
        string signature = "t=1630000000,v2=invalid_signature";

        try
        {
            AuthsignalClient.Webhook.ConstructEvent(payload, signature);

            Assert.Fail("Expected an AuthsignalException to be thrown");
        }
        catch (Webhook.InvalidSignatureException ex)
        {
            Assert.Equal("Timestamp is outside the tolerance zone.", ex.Message);
        }
    }

    [Fact]
    public void TestInvalidComputedSignature()
    {
        string payload = "{}";
        string signature = $"t={DateTimeOffset.UtcNow.ToUnixTimeSeconds()},v2=invalid_signature";

        var ex = Assert.Throws<Webhook.InvalidSignatureException>(
            () => AuthsignalClient.Webhook.ConstructEvent(payload, signature));

        Assert.Equal("Signature mismatch.", ex.Message);
    }

    [Fact]
    public void TestValidSignature()
    {
        string payload = "{"
               + "\"version\":1,"
               + "\"id\":\"bc1598bc-e5d6-4c69-9afb-1a6fe3469d6e\","
               + "\"source\":\"https://authsignal.com\","
               + "\"time\":\"2025-02-20T01:51:56.070Z\","
               + "\"tenantId\":\"7752d28e-e627-4b1b-bb81-b45d68d617bc\","
               + "\"type\":\"email.created\","
               + "\"data\":{"
               + "\"to\":\"chris@authsignal.com\","
               + "\"code\":\"157743\","
               + "\"userId\":\"b9f74d36-fcfc-4efc-87f1-3664ab5a7fb0\","
               + "\"actionCode\":\"accountRecovery\","
               + "\"idempotencyKey\":\"ba8c1a7c-775d-4dff-9abe-be798b7b8bb9\","
               + "\"verificationMethod\":\"EMAIL_OTP\""
               + "}"
               + "}";

        int tolerance = -1;

        string signature = SignPayload(payload, 1740016316);

        var eventObj = AuthsignalClient.Webhook.ConstructEvent(payload, signature, tolerance);

        Assert.NotNull(eventObj);

        Assert.Equal(1, eventObj.Version);

        var actionCode = eventObj.Data?.GetValueOrDefault("actionCode").GetString();

        Assert.Equal("accountRecovery", actionCode);
    }

    [Fact]
    public void TestValidSignatureWhenTwoApiKeysActive()
    {
        string payload = "{"
               + "\"version\":1,"
               + "\"id\":\"af7be03c-ea8f-4739-b18e-8b48fcbe4e38\","
               + "\"source\":\"https://authsignal.com\","
               + "\"time\":\"2025-02-20T01:47:17.248Z\","
               + "\"tenantId\":\"7752d28e-e627-4b1b-bb81-b45d68d617bc\","
               + "\"type\":\"email.created\","
               + "\"data\":{"
               + "\"to\":\"chris@authsignal.com\","
               + "\"code\":\"718190\","
               + "\"userId\":\"b9f74d36-fcfc-4efc-87f1-3664ab5a7fb0\","
               + "\"actionCode\":\"accountRecovery\","
               + "\"idempotencyKey\":\"68d68190-fac9-4e91-b277-c63d31d3c6b1\","
               + "\"verificationMethod\":\"EMAIL_OTP\""
               + "}"
               + "}";

        int tolerance = -1;

        string signature = $"{SignPayload(payload, 1740016037)},v2=invalid_signature";

        var eventObj = AuthsignalClient.Webhook.ConstructEvent(payload, signature, tolerance);

        Assert.NotNull(eventObj);
    }

    [Fact]
    public void TestEventWithCustomVariables()
    {
        string payload = "{"
               + "\"version\":1,"
               + "\"id\":\"7f0d5e6a-3c1b-4a2e-9d8f-5b6c7a8e9f01\","
               + "\"source\":\"https://authsignal.com\","
               + "\"time\":\"2025-02-20T01:51:56.070Z\","
               + "\"tenantId\":\"7752d28e-e627-4b1b-bb81-b45d68d617bc\","
               + "\"type\":\"sms.created\","
               + "\"data\":{"
               + "\"code\":\"123456\","
               + "\"to\":\"+919888123456\","
               + "\"userId\":\"b9f74d36-fcfc-4efc-87f1-3664ab5a7fb0\","
               + "\"actionCode\":\"smsVerify\","
               + "\"customVariables\":{"
               + "\"action_journeyType\":\"ForgotChangePassword\","
               + "\"action_transactionAmount\":100,"
               + "\"user_isVerified\":true,"
               + "\"user_roles\":[\"admin\",\"ops\"]"
               + "}"
               + "}"
               + "}";

        int tolerance = -1;

        string signature = SignPayload(payload, 1740016316);

        var eventObj = AuthsignalClient.Webhook.ConstructEvent(payload, signature, tolerance);

        Assert.NotNull(eventObj);

        Assert.Equal("smsVerify", eventObj.Data?.GetValueOrDefault("actionCode").GetString());

        var customVariables = eventObj.Data?.GetValueOrDefault("customVariables");

        Assert.Equal("ForgotChangePassword", customVariables?.GetProperty("action_journeyType").GetString());

        Assert.Equal(100, customVariables?.GetProperty("action_transactionAmount").GetInt32());

        Assert.True(customVariables?.GetProperty("user_isVerified").GetBoolean());

        Assert.Equal("admin", customVariables?.GetProperty("user_roles")[0].GetString());
    }

    [Fact]
    public void TestLogEventBatch()
    {
        string payload = "{"
               + "\"records\":[{"
               + "\"version\":1,"
               + "\"id\":\"5d1d6b5c-4b6f-4f5a-9c3e-2f7a1b8d4e6c\","
               + "\"source\":\"https://authsignal.com\","
               + "\"time\":\"2025-02-20T01:51:56.070Z\","
               + "\"tenantId\":\"7752d28e-e627-4b1b-bb81-b45d68d617bc\","
               + "\"type\":\"action.log_created\","
               + "\"record\":{\"userId\":\"b9f74d36-fcfc-4efc-87f1-3664ab5a7fb0\",\"state\":\"ALLOW\"}"
               + "}]"
               + "}";

        string signature = SignPayload(payload, 1740016316);

        var batch = AuthsignalClient.Webhook.ConstructLogEventBatch(payload, signature, -1);

        var logEvent = Assert.Single(batch.Records);

        Assert.Equal("action.log_created", logEvent.Type);
        Assert.Equal("ALLOW", logEvent.Record?["state"].GetString());
    }

    [Fact]
    public void TestLogEventBatchPassedToConstructEventIsRejectedWithGuidance()
    {
        string payload = "{"
               + "\"records\":[]"
               + "}";

        string signature = SignPayload(payload, 1740016316);

        var ex = Assert.Throws<Webhook.InvalidPayloadException>(
            () => AuthsignalClient.Webhook.ConstructEvent(payload, signature, -1));

        Assert.Contains("ConstructLogEventBatch", ex.Message);
    }

    [Fact]
    public void TestInvalidPayload()
    {
        const string payload = "not-json";

        string signature = SignPayload(payload, 1740016316);

        var ex = Assert.Throws<Webhook.InvalidPayloadException>(
            () => AuthsignalClient.Webhook.ConstructEvent(payload, signature, -1));

        Assert.Equal("Payload format is invalid.", ex.Message);
        Assert.NotNull(ex.InnerException);
    }

    [Fact]
    public void TestMissingRequiredEnvelopeField()
    {
        const string payload = "{\"version\":1,\"type\":\"sms.created\",\"data\":{}}";

        string signature = SignPayload(payload, 1740016316);

        var ex = Assert.Throws<Webhook.InvalidPayloadException>(
            () => AuthsignalClient.Webhook.ConstructEvent(payload, signature, -1));

        Assert.Equal("Payload is missing required field 'id'.", ex.Message);
    }
}
