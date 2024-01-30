namespace Authsignal.Tests;

public class ClientTests : TestBase
{
    [Fact]
    public async Task GetUser()
    {
        var response = await AuthsignalClient.GetUser(new(UserId: Configuration["UserId"]));

        Assert.NotNull(response);
    }

    [Fact]
    public async Task Track()
    {
        var response = await AuthsignalClient.Track(new(UserId: Configuration["UserId"], Action: "Login"));

        Assert.NotNull(response);
    }

    [Fact]
    public async Task GetAction()
    {
        var trackResponse = await AuthsignalClient.Track(new(UserId: Configuration["UserId"], Action: "Login"));

        var response = await AuthsignalClient.GetAction(new(UserId: Configuration["UserId"], Action: "Login", IdempotencyKey: trackResponse.IdempotencyKey));

        Assert.NotNull(response);
    }

    [Fact]
    public async Task ValidateChallenge()
    {
        var trackResponse = await AuthsignalClient.Track(new(UserId: Configuration["UserId"], Action: "Login"));

        var request = new ValidateChallengeRequest(UserId: Configuration["UserId"], Token: trackResponse.Token);

        var response = await AuthsignalClient.ValidateChallenge(request);

        Assert.NotNull(response);
    }

    [Fact]
    public async Task EnrollVerifiedAuthenticator()
    {
        var response = await AuthsignalClient.EnrollVerifiedAuthenticator(new(UserId: Configuration["UserId"], OobChannel: OobChannel.SMS, PhoneNumber: "+6427000000"));

        Assert.NotNull(response);
    }
}
