using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Api.Data.Context;

public class IdentityContextFactory : IDesignTimeDbContextFactory<IdentityContext>
{
    private readonly string connectionString = Environment.GetEnvironmentVariable("DB_CONNECTION_AUTH", EnvironmentVariableTarget.Machine)!;
    public IdentityContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityContext>();

        optionsBuilder.UseLazyLoadingProxies().UseSqlServer(connectionString);

        return new IdentityContext(optionsBuilder.Options);
    }
}