namespace Authsignal.Tests;

public class ClientTests : TestBase
{
    [Fact]
    public async Task GetUser()
    {
        var response = await AuthsignalClient.GetUser(new(UserId: "TestUserId"));

        Assert.NotNull(response);
    }

    [Fact]
    public async Task Track()
    {
        var response = await AuthsignalClient.Track(new(UserId: "TestUserId", Action: "Login"));

        Assert.NotNull(response);
    }

    [Fact]
    public async Task GetAction()
    {
        var response = await AuthsignalClient.GetAction(new(UserId: "TestUserId", Action: "Login", IdempotencyKey: Guid.NewGuid().ToString()));

        Assert.NotNull(response);
    }

    [Fact]
    public async Task ValidateChallenge()
    {
        var response = await AuthsignalClient.ValidateChallenge(new(UserId: "TestUserId", Token: Configuration["Token"]));

        Assert.NotNull(response);
    }

    [Fact]
    public async Task EnrollVerifiedAuthenticator()
    {
        var response = await AuthsignalClient.EnrollVerifiedAuthenticator(new(UserId: "TestUserId", OobChannel: OobChannel.SMS, PhoneNumber: "+6427000000"));

        Assert.NotNull(response);
    }
}
