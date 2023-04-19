namespace MicroserviceOpenIddictTemplate.Identity.Endpoints.Account.ViewModel;

public class IdTokenResponse
{
    public string AccessToken { get; set; } = null!;
    public string RefreshToken { get; set; } = null!;
}