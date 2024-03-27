using Api.Data.Context;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace Api.CrossCutting.Configuration;

public class IdentityConfig
{
    public static void ConfigureDependenciesIdentity(IServiceCollection service, IConfiguration configuration, string chave)
    {
        service.AddDbContext<IdentityContext>(options =>
        options.UseSqlServer(Environment.GetEnvironmentVariable(chave, EnvironmentVariableTarget.Machine)));

        #region JSON WEB TOKEN

        var appSettingsSection = configuration.GetSection("AppSettings");
        service.Configure<AppSettings>(appSettingsSection);

        var appSettings = appSettingsSection.Get<AppSettings>();
        var key = Encoding.ASCII.GetBytes(appSettings!.Secret);

        service.AddAuthentication(x =>
        {
            x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(x =>
        {
            x.RequireHttpsMetadata = true;
            x.SaveToken = true;
            x.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidAudience = appSettings.ValidoEm,
                ValidIssuer = appSettings.Emissor
            };
        });

        #endregion 

    }
}
