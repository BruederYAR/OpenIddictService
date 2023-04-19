using System.ComponentModel.DataAnnotations;

namespace MicroserviceOpenIddictTemplate.Identity.Endpoints.Account.ViewModel;

public class LoginRequest
{
    [Required]
    public string Login { get; set; } = null!;

    [Required]
    public string Password { get; set; } = null!;
}