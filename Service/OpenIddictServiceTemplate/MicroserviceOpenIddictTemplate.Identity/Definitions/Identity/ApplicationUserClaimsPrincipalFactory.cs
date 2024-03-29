﻿using System.Collections.Immutable;
using System.Security.Claims;
using MicroserviceOpenIddictTemplate.DAL.Models.Identity;
using MicroserviceOpenIddictTemplate.Identity.Base.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace MicroserviceOpenIddictTemplate.Identity.Definitions.Identity;

public class ApplicationUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<ApplicationUser, ApplicationRole>
{
    private UserManager<ApplicationUser> _userManager;

    public ApplicationUserClaimsPrincipalFactory(
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> roleManager,
        IOptions<IdentityOptions> optionsAccessor)
        : base(userManager, roleManager, optionsAccessor)
    {
        _userManager = userManager;
    }

    public override async Task<ClaimsPrincipal> CreateAsync(ApplicationUser user)
    {
        var principal = await base.CreateAsync(user);
        var claimIdentity = (ClaimsIdentity)principal.Identity!;
        
        if (!string.IsNullOrWhiteSpace(user.UserName) && 
            string.IsNullOrEmpty(ClaimsHelper.GetValue<string>(claimIdentity,OpenIddictConstants.Claims.Name)))
        {
            ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim(OpenIddictConstants.Claims.Name, user.UserName));
        }

        if (!string.IsNullOrWhiteSpace(user.FirstName) &&
            string.IsNullOrEmpty(ClaimsHelper.GetValue<string>(claimIdentity,OpenIddictConstants.Claims.GivenName)))
        {
            ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim(OpenIddictConstants.Claims.GivenName, user.FirstName));
        }

        if (!string.IsNullOrWhiteSpace(user.LastName) &&
            string.IsNullOrEmpty(ClaimsHelper.GetValue<string>(claimIdentity,OpenIddictConstants.Claims.FamilyName)))
        {
            ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim(OpenIddictConstants.Claims.FamilyName, user.LastName));
        }
        if (!string.IsNullOrWhiteSpace(user.Email) &&
            string.IsNullOrEmpty(ClaimsHelper.GetValue<string>(claimIdentity,OpenIddictConstants.Claims.Email)))
        {
            ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim(OpenIddictConstants.Claims.Email, user.Email));
        }
        if (!string.IsNullOrWhiteSpace(user.PhoneNumber) &&
            string.IsNullOrEmpty(ClaimsHelper.GetValue<string>(claimIdentity,OpenIddictConstants.Claims.PhoneNumber)))
        {
            ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim(OpenIddictConstants.Claims.PhoneNumber, user.PhoneNumber));
        }
        if(!string.IsNullOrWhiteSpace(user.Id.ToString()) &&
           string.IsNullOrEmpty(ClaimsHelper.GetValue<string>(claimIdentity,OpenIddictConstants.Claims.Subject)))
        {
            ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim(OpenIddictConstants.Claims.Subject, user.Id.ToString()));
        }

        if (string.IsNullOrWhiteSpace(ClaimsHelper.GetValue<string>(claimIdentity, OpenIddictConstants.Claims.Role)))
        {
            principal.SetClaims(OpenIddictConstants.Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());
        }
        
        return principal;
    }

}