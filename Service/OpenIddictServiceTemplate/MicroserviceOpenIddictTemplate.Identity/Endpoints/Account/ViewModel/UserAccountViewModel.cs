namespace MicroserviceOpenIddictTemplate.Identity.Endpoints.Account.ViewModel;

public class UserAccountViewModel
{
    public Guid Id { get; set; }
    public string FirstName { get; set; } = null!;
    public string LastName { get; set; } = null!;
    public string? Email { get; set; }
    public List<string>? Roles { get; set; }
    public string? PhoneNumber { get; set; }
    public string? PositionName { get; set; }
}