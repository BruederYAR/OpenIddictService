using Microsoft.AspNetCore.Identity;

namespace MicroserviceOpenIddictTemplate.DAL.Models.Identity;

public class ApplicationUser : IdentityUser<Guid>
{
    public string FirstName { get; set; } = null!;
    public string LastName { get; set; } = null!;
    public string? MiddleName { get; set; }

    public DateTime BirthDate { get; set; }
}
