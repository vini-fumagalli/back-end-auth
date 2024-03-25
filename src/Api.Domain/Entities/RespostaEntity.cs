namespace Api.Domain.Entities;

public class RespostaEntity
{
    public bool Sucesso { get; set; }
    public object? Resposta { get; set; }
    public string? Mensagem { get; set; }

    public RespostaEntity() { }

    public RespostaEntity(
        bool sucesso,
        object? resposta
    )
    {
        Sucesso = sucesso;
        Resposta = resposta;
    }

    public RespostaEntity(
        bool sucesso,
        string mensagem
    )
    {
        Sucesso = sucesso;
        Mensagem = mensagem;
    }

    public RespostaEntity(
        bool sucesso,
        object? resposta,
        string mensagem
    )
    {
        Sucesso = sucesso;
        Resposta = resposta;
        Mensagem = mensagem;
    }
}