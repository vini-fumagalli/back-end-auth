namespace Api.Domain.Entities;

public class RespostaEntity
{
    public bool Sucesso { get; set; }
    public object? Data { get; set; }
    public string? Mensagem { get; set; }

    public RespostaEntity() { }

    public RespostaEntity(
        bool sucesso,
        object? resposta
    )
    {
        Sucesso = sucesso;
        Data = resposta;
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
        Data = resposta;
        Mensagem = mensagem;
    }
}