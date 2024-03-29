﻿using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace MicroserviceOpenIddictTemplate.Identity.Base.Definition;

public class Definition : IDefinition
{
    public virtual bool Enabled => true;

    public virtual void ConfigureApplicationAsync(WebApplication app)
    {
    }

    public virtual void ConfigureServicesAsync(IServiceCollection services, WebApplicationBuilder builder)
    {
    }
}