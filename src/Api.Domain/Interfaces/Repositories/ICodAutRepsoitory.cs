using Api.Domain.ViewModels;

namespace Api.Domain.Interfaces.Repositories;

public interface ICodAutRepository
{
    Task GerarCodEnviarEmail(string userEmail);
    Task<bool> CodigoValido(CodAutViewModel vm);
}