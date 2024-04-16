using System.Net;
using System.Net.Mail;
using Api.Data.Context;
using Api.Domain.Entities;
using Api.Domain.Interfaces.Repositories;
using Api.Domain.ViewModels;
using Microsoft.EntityFrameworkCore;

namespace Api.Data.Repositories;

public class CodAutRepository : ICodAutRepository
{
    private readonly MyContext _context;
    private readonly DbSet<CodAutEntity> _dataset;
    private static readonly SmtpClient _smtpClient = new("smtp.office365.com", 587)
    {
        Credentials = new NetworkCredential()
        {
            UserName = "app.angular.vini.fumagalli@hotmail.com",
            Password = Environment.GetEnvironmentVariable("EMAIL_COD_AUT_PASSWORD", EnvironmentVariableTarget.Machine),
        },
        EnableSsl = true
    };

    public CodAutRepository(MyContext context)
    {
        _context = context;
        _dataset = _context.Set<CodAutEntity>();
    }
    public async Task GerarCodEnviarEmail(string userEmail)
    {
        try
        {
            var random = new Random();
            var codAut = random.Next(100000, 1000000).ToString();
            var codAutObj = new CodAutEntity(userEmail, codAut);

            await Task.WhenAll(
                EnviarEmail(userEmail, codAut),
                CreateOrUpdate(codAutObj)
            );

            return;
        }
        catch (Exception ex)
        {
            throw new Exception("ERRO AO REGISTRAR CÓDIGO DE AUTENTICAÇÃO => ", ex);
        }
    }

    private async Task CreateOrUpdate(CodAutEntity entity)
    {
        if (!await CodAutExists(entity.UserEmail))
        {
            await _dataset.AddAsync(entity);
            await _context.SaveChangesAsync();
            return;
        }

        var entityToUpdate = await _dataset.SingleOrDefaultAsync(c => c.UserEmail == entity.UserEmail);

        _dataset
        .Entry(entityToUpdate!)
        .CurrentValues
        .SetValues(entity);

        await _context.SaveChangesAsync();
        return;
    }

    private async Task<bool> CodAutExists(string userEmail)
    {
        return await _dataset.AnyAsync(c => c.UserEmail == userEmail);
    }

    private static async Task EnviarEmail(string userEmail, string codAut)
    {
        var smtpUsername = "app.angular.vini.fumagalli@hotmail.com";
        var toAdress = userEmail;

        var message = new MailMessage(smtpUsername, toAdress)
        {
            Subject = "Complete seu cadastro!!",
            Body = $"Esse é seu código de autenticação: {codAut}"
        };

        try
        {
            await _smtpClient.SendMailAsync(message);
        }
        catch (Exception ex)
        {
            throw new Exception("ERRO AO ENVIAR EMAIL => ", ex);
        }
        finally
        {
            message.Dispose();
        }
    }

    public async Task<bool> CodigoValido(CodAutViewModel vm)
    {
        return await _dataset
                    .AnyAsync(c =>
                        c.UserEmail == vm.Email &&
                        c.CodAut == vm.CodAut);
    }
}