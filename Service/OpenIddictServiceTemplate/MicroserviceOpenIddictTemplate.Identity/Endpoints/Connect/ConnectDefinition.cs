using System.Security.Claims;
using MicroserviceOpenIddictTemplate.DAL.Models.Identity;
using MicroserviceOpenIddictTemplate.Identity.Application.Services;
using MicroserviceOpenIddictTemplate.Identity.Base.Definition;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace MicroserviceOpenIddictTemplate.Identity.Endpoints.Connect;

public class ConnectDefinition : Definition
{
    public override void ConfigureApplicationAsync(WebApplication app)
    {
        app.MapPost("~/connect/token", Token).ExcludeFromDescription();
        
        app.MapPost("~/connect/authorize", Authorize).ExcludeFromDescription();
        app.MapGet("~/connect/authorize", Authorize).ExcludeFromDescription();
    }
    
    private async Task<IResult> Token(
        HttpContext httpContext,
        IOpenIddictScopeManager manager,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IAccountService accountService)
    {
        var request = httpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        //if (request.Scope is null)
        //{
        //    return Results.Problem("The specified grant type is not supported.");
        //}

        if (request.IsClientCredentialsGrantType())
        {
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // Subject or sub is a required field, we use the client id as the subject identifier here.
            identity.AddClaim(OpenIddictConstants.Claims.Subject, request.ClientId!);
            identity.AddClaim(OpenIddictConstants.Claims.ClientId, request.ClientId!);

            // Don't forget to add destination otherwise it won't be added to the access token.
            if (!string.IsNullOrEmpty(request.Scope))
            {
                identity.AddClaim(OpenIddictConstants.Claims.Scope, request.Scope!, OpenIddictConstants.Destinations.AccessToken);
            }

            var claimsPrincipal = new ClaimsPrincipal(identity);

            claimsPrincipal.SetScopes(request.GetScopes());
            return Results.SignIn(claimsPrincipal, new AuthenticationProperties(), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsPasswordGrantType())
        {
            var user = await userManager.FindByNameAsync(request.Username);
            if (user == null)
            {
                return Results.Problem("Invalid operation");
            }
            // Ensure the user is allowed to sign in
            if (!await signInManager.CanSignInAsync(user))
            {
                return Results.Problem("Invalid operation");
            }
            // Ensure the user is not already locked out
            if (userManager.SupportsUserLockout && await userManager.IsLockedOutAsync(user))
            {
                return Results.Problem("Invalid operation");
            }
            // Ensure the password is valid
            if (!await userManager.CheckPasswordAsync(user, request.Password))
            {
                if (userManager.SupportsUserLockout)
                {
                    await userManager.AccessFailedAsync(user);
                }

                return Results.Problem("Invalid operation");
            }
            // Reset the lockout count
            if (userManager.SupportsUserLockout)
            {
                await userManager.ResetAccessFailedCountAsync(user);
            }

            var principal = await accountService.GetPrincipalForUserAsync(user);
            return Results.SignIn(principal, null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsAuthorizationCodeGrantType())
        {
            var authenticateResult = await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var claimsPrincipal = authenticateResult.Principal;
            return Results.SignIn(claimsPrincipal!, null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsDeviceCodeGrantType())
        {
            var result = await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // Retrieve the user profile corresponding to the authorization code/refresh token.
            var user = await userManager.FindByIdAsync(result.Principal.GetClaim(OpenIddictConstants.Claims.Subject));
            if (user is null)
            {
                return Results.Forbid(
                    authenticationSchemes: new List<string> {OpenIddictServerAspNetCoreDefaults.AuthenticationScheme},
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                    }));
            }

            // Ensure the user is still allowed to sign in.
            if (!await signInManager.CanSignInAsync(user))
            {
                return Results.Forbid(
                    authenticationSchemes: new List<string> {OpenIddictServerAspNetCoreDefaults.AuthenticationScheme},
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in."
                    }));
            }

            var identity = new ClaimsIdentity(result.Principal.Claims,
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: OpenIddictConstants.Claims.Name,
                roleType: OpenIddictConstants.Claims.Role);

            identity.SetDestinations(GetDestinations);

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            return Results.SignIn(new ClaimsPrincipal(identity),null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return Results.Problem("The specified grant type is not supported.");
    }   
    
    private async Task<IResult> Authorize(
        HttpContext httpContext,
        IOpenIddictScopeManager scopeManager,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager)
    {
        var request = httpContext.Request;
        var iddictRequest = httpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Retrieve the user principal stored in the authentication cookie.
        var result = await httpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        if (!result.Succeeded)
        {
            return Results.Challenge(new AuthenticationProperties
            {
                RedirectUri = request.PathBase + request.Path + QueryString.Create(request.HasFormContentType
                ? request.Form.ToList()
                : request.Query.ToList())
            },
            new List<string> { CookieAuthenticationDefaults.AuthenticationScheme });
        }

        // ATTENTION:  If you use are "IN-Memory" mode, then system cannot track user that recreated every time on start. You should clear cookies (site data) in browser.
        var user = await userManager.GetUserAsync(result.Principal) ?? throw new InvalidOperationException("The user details cannot be retrieved.");

        var application = await applicationManager.FindByClientIdAsync(iddictRequest.ClientId!) ?? throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
        var applicationId = await applicationManager.GetIdAsync(application);
        var userId = await userManager.GetUserIdAsync(user);

        var authorizations = await authorizationManager.FindAsync(
        subject: userId,
        client: applicationId!,
        status: OpenIddictConstants.Statuses.Valid,
        type: OpenIddictConstants.AuthorizationTypes.Permanent,
        scopes: iddictRequest.GetScopes()).ToListAsync();

        switch (await applicationManager.GetConsentTypeAsync(application))
        {
            // If the consent is external (e.g when authorizations are granted by a sysadmin),
            // immediately return an error if no authorization can be found in the database.
            case OpenIddictConstants.ConsentTypes.External when !authorizations.Any():
                return Results.Forbid(
                        authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme },
                        properties: new AuthenticationProperties(new Dictionary<string, string>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.ConsentRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                "The logged in user is not allowed to access this client application."
                        }!));

            // If the consent is implicit or if an authorization was found,
            // return an authorization response without displaying the consent form.
            case OpenIddictConstants.ConsentTypes.Implicit:
            case OpenIddictConstants.ConsentTypes.External when authorizations.Any():
            case OpenIddictConstants.ConsentTypes.Explicit when authorizations.Any() && !iddictRequest.HasPrompt(OpenIddictConstants.Prompts.Consent):

                var principal = await signInManager.CreateUserPrincipalAsync(user);

                // Note: in this sample, the granted scopes match the requested scope
                // but you may want to allow the user to uncheck specific scopes.
                // For that, simply restrict the list of scopes before calling SetScopes.

                principal.SetScopes(iddictRequest.GetScopes());
                principal.SetResources(await scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());

                // Automatically create a permanent authorization to avoid requiring explicit consent
                // for future authorization or token requests containing the same scopes.
                var authorization = authorizations.LastOrDefault() ?? await authorizationManager.CreateAsync(
                    principal: principal,
                    subject: await userManager.GetUserIdAsync(user),
                    client: applicationId!,
                    type: OpenIddictConstants.AuthorizationTypes.Permanent,
                    scopes: principal.GetScopes());

                principal.SetAuthorizationId(await authorizationManager.GetIdAsync(authorization));

                principal.SetDestinations(static claim => claim.Type switch
                {
                    // If the "profile" scope was granted, allow the "name" claim to be
                    // added to the access and identity tokens derived from the principal.
                    OpenIddictConstants.Claims.Name when claim.Subject.HasScope(OpenIddictConstants.Scopes.Profile) => new[]
                    {
                        OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken
                    },

                    // Never add the "secret_value" claim to access or identity tokens.
                    // In this case, it will only be added to authorization codes,
                    // refresh tokens and user/device codes, that are always encrypted.
                    "secret_value" => Array.Empty<string>(),

                    // Otherwise, add the claim to the access tokens only.
                    _ => new[] { OpenIddictConstants.Destinations.AccessToken }
                });



                return Results.SignIn(principal, null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // At this point, no authorization was found in the database and an error must be returned
            // if the client application specified prompt=none in the authorization request.
            case OpenIddictConstants.ConsentTypes.Explicit when iddictRequest.HasPrompt(OpenIddictConstants.Prompts.None):
            case OpenIddictConstants.ConsentTypes.Systematic when iddictRequest.HasPrompt(OpenIddictConstants.Prompts.None):
                return Results.Forbid(
                        authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme },
                        properties: new AuthenticationProperties(new Dictionary<string, string>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.ConsentRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                "Interactive user consent is required."
                        }!));

            // In every other case, render the consent form.
            default:
                return Results.Challenge(
                    authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme },
                    properties: new AuthenticationProperties { RedirectUri = "/" });
        }
    }
    
    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        // Note: by default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
        // whether they should be included in access tokens, in identity tokens or in both.

        switch (claim.Type)
        {
            case OpenIddictConstants.Claims.Name:
                yield return OpenIddictConstants.Destinations.AccessToken;

                if (claim.Subject.HasScope(OpenIddictConstants.Permissions.Scopes.Profile))
                    yield return OpenIddictConstants.Destinations.IdentityToken;

                yield break;

            case OpenIddictConstants.Claims.Email:
                yield return OpenIddictConstants.Destinations.AccessToken;

                if (claim.Subject.HasScope(OpenIddictConstants.Permissions.Scopes.Email))
                    yield return OpenIddictConstants.Destinations.IdentityToken;

                yield break;

            case OpenIddictConstants.Claims.Role:
                yield return OpenIddictConstants.Destinations.AccessToken;

                if (claim.Subject.HasScope(OpenIddictConstants.Permissions.Scopes.Roles))
                    yield return OpenIddictConstants.Destinations.IdentityToken;

                yield break;

            // Never include the security stamp in the access and identity tokens, as it's a secret value.
            case "AspNet.Identity.SecurityStamp": yield break;

            default:
                yield return OpenIddictConstants.Destinations.AccessToken;
                yield break;
        }
    }
}