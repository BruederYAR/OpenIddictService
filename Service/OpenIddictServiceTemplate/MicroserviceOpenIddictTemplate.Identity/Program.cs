using MicroserviceOpenIddictTemplate.Identity.Base.Definition;

try
{
    var builder = WebApplication.CreateBuilder(args);
    builder.Services.AddDefinitions(builder, typeof(Program));

    var app = builder.Build();
    app.UseDefinitions();

    app.Run();
}
catch (Exception ex)
{
    
}