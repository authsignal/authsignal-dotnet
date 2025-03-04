namespace Authsignal.Tests;

public class WebhookTests : TestBase
{
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

        string signature = "t=1740016316,v2=NwFcIT68pK7g+m365Jj4euXj/ke3GSnkTpMPcRVi5q4";

        try
        {
            var eventObj = AuthsignalClient.Webhook.ConstructEvent(payload, signature, tolerance);

            Assert.NotNull(eventObj);

            Assert.Equal(1, eventObj.Version);

            var actionCode = eventObj.Data?.GetValueOrDefault("actionCode");

            Assert.Equal("accountRecovery", actionCode);
        }
        catch
        {
            Assert.Fail("Expected a valid event to be constructed");
        }
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

        string signature = "t=1740016037,v2=zI5rg1XJtKH8dXTX9VCSwy07qTPJliXkK9ppgNjmzqw,v2=KMg8mXXGO/SmNNmcszKXI4UaEVHLc21YNWthHfispQo";

        try
        {
            var eventObj = AuthsignalClient.Webhook.ConstructEvent(payload, signature, tolerance);
            Assert.NotNull(eventObj);
        }
        catch
        {
            Assert.Fail("Expected a valid event to be constructed");
        }
    }
}