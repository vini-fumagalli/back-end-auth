using Api.Data.Context;
using Api.Data.Repositories;
using Api.Domain.Interfaces.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Api.CrossCutting.DependencyInjection;

public class ConfigureRepository
{
    public static void ConfigureDependenciesRepository(IServiceCollection service, string chave)
    {
        service.AddScoped<ICodAutRepository, CodAutRepository>();

        var connectionString = Environment.GetEnvironmentVariable(chave, EnvironmentVariableTarget.Machine);
        service.AddDbContext<MyContext>(options => options.UseSqlServer(connectionString));
    }
}