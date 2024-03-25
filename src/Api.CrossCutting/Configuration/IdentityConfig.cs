using Api.Data.Context;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using System.Text;

namespace Api.CrossCutting.Configuration;

public class IdentityConfig
{
    public static void ConfigureDependenciesIdentity(IServiceCollection service, IConfiguration configuration, string chave)
    {
        service.AddDbContext<IdentityContext>(options =>
        options.UseSqlServer(Environment.GetEnvironmentVariable(chave, EnvironmentVariableTarget.Machine)));

        service.AddIdentityCore<IdentityUser>()
                .AddRoles<IdentityRole>()
                .AddEntityFrameworkStores<IdentityContext>();
        // .AddTokenProvider<DefaultUserConfirmation<IdentityUser>>("email")

        //JWT

        // var appSettingsSection = configuration.GetSection("AppSettings");
        // service.Configure<AppSettings>(appSettingsSection);

    }
}
