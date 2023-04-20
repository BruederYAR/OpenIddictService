using System.Security.Claims;
using MicroserviceOpenIddictTemplate.DAL.Domain;
using MicroserviceOpenIddictTemplate.Identity.Application.Services;
using MicroserviceOpenIddictTemplate.Identity.Base.Attributes;
using MicroserviceOpenIddictTemplate.Identity.Base.Definition;
using MicroserviceOpenIddictTemplate.Identity.Endpoints.Account.ViewModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Serilog;

namespace MicroserviceOpenIddictTemplate.Identity.Endpoints.Account;

public class AccountEndPoint : Definition
{
    public override void ConfigureApplicationAsync(WebApplication app)
    {
        app.MapPost("~/api/account/register", Register).WithOpenApi();
        app.MapGet("~/api/account/getclaims", GetClaims).WithOpenApi();
    }

    [ProducesResponseType(200)]
    [ProducesResponseType(401)]
    [FeatureGroupName("Account")]
    [Authorize(AuthenticationSchemes = AuthData.AuthenticationSchemes)]
    private async Task<IResult> GetClaims( 
        [FromServices] IHttpContextAccessor httpContextAccessor)
    {
        var user = httpContextAccessor.HttpContext!.User;
        var claims = ((ClaimsIdentity)user.Identity!).Claims;
        var result = claims.Select(x => new { Type = x.Type, ValueType = x.ValueType, Value = x.Value });
        Log.Information($"Current user {user.Identity.Name} have following climes {result}");
        return Results.Ok(result);
    }

    [ProducesResponseType(200)]
    [ProducesResponseType(401)]
    [FeatureGroupName("Account")]
    private async Task<IResult> Register(
        [FromBody] RegisterViewModel model,
        [FromServices] IAccountService accountService,
        [FromServices] CancellationToken cancellationToken)
    {
        var userProfile = await accountService.RegisterAsync(model, cancellationToken);
        Log.Information($"{userProfile.FirstName} {userProfile.LastName} has be registered");
        return Results.Ok(userProfile);
    }
}