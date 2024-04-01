namespace Api.Domain.ViewModels;

public class LoginResponseViewModel
{
    public string AccessToken { get; set; } = "";
    public DateTime ExpiresAt { get; set; }
    public UserTokenViewModel? UserToken { get; set; }
}