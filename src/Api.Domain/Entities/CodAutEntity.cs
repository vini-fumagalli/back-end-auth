namespace Api.Domain.Entities;

public class CodAutEntity
{
    public string UserEmail { get; set; } = "";
    public string CodAut { get; set; } = "";

    public CodAutEntity(string userEmail, string codAut)
    {
        UserEmail = userEmail;
        CodAut = codAut;
    }
}