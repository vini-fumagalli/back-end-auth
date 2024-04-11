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

            await CreateOrUpdate(codAutObj);

            EnviarEmail(userEmail, codAut);
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

    private static void EnviarEmail(string userEmail, string codAut)
    {
        var smtpHost = "smtp.office365.com";
        var smtpPort = 587;
        var smtpUsername = "app.angular.vini.fumagalli@hotmail.com";
        var smtpPassword = Environment.GetEnvironmentVariable("EMAIL_COD_AUT_PASSWORD", EnvironmentVariableTarget.Machine);
        var toAdress = userEmail;

        var message = new MailMessage(smtpUsername, toAdress)
        {
            Subject = "Complete seu cadastro!!",
            Body = $"Esse é seu código de autenticação: {codAut}"
        };

        var smtpClient = new SmtpClient(smtpHost, smtpPort)
        {
            Credentials = new NetworkCredential(smtpUsername, smtpPassword),
            EnableSsl = true
        };

        try
        {
            smtpClient.Send(message);
        }
        catch (Exception ex)
        {
            throw new Exception("ERRO AO ENVIAR EMAIL => ", ex);
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