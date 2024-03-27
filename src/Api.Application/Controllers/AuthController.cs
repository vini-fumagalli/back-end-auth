using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Api.CrossCutting.Configuration;
using Api.Domain.Entities;
using Api.Domain.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Api.Application.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly AppSettings _appSettings;

    public AuthController(
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IOptions<AppSettings> appSettings
    )
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _appSettings = appSettings.Value;
    }

    [HttpPost("sign-up")]
    public async Task<ActionResult<RespostaEntity>> SignUp(RegisterUserViewModel registerUser)
    {
        string msg;

        if (!ModelState.IsValid) return BadRequest();

        var user = new IdentityUser
        {
            UserName = registerUser.Email,
            Email = registerUser.Email,
            EmailConfirmed = true
        };

        var result = await _userManager.CreateAsync(user, registerUser.Password);

        if (result.Succeeded)
        {
            await _signInManager.SignInAsync(user, false);
            msg = "Usuário cadastrado com sucesso";
            var data = await GerarJwt(user.Email);
            return Ok(new RespostaEntity(true, data, msg));
        }

        msg = "Falha ao tentar realizar cadastro";
        return BadRequest(new RespostaEntity(false, msg));
    }

    [HttpPost("sign-in")]
    public async Task<ActionResult<RespostaEntity>> Login(LoginUserViewModel loginUser)
    {
        string msg;

        if (!ModelState.IsValid) return BadRequest();

        var result = await _signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, false, true);

        if (result.Succeeded)
        {
            msg = "Usuário logado com sucesso";
            return Ok(new RespostaEntity(true, await GerarJwt(loginUser.Email), msg));
        }

        if (result.IsLockedOut)
        {
            msg = "Usuário temporariamente bloqueado por tentativas inválidas";
            return BadRequest(new RespostaEntity(false, msg));
        }

        msg = "Usúario ou senha inválidos";
        return BadRequest(new RespostaEntity(false, msg));
    }

    [Authorize]
    [HttpGet("saudacao")]
    public string Saudacao()
    {
        return "Olá, Você está autenticado :)";
    }

    public virtual async Task<LoginResponseViewModel> GerarJwt(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        var claims = await _userManager.GetClaimsAsync(user!);
        var userRoles = await _userManager.GetRolesAsync(user!);

        claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user!.Id));
        claims.Add(new Claim(JwtRegisteredClaimNames.Email, user!.Email!));
        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
        claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, ToUnixEpochDate(DateTime.UtcNow).ToString()));
        claims.Add(new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(DateTime.UtcNow).ToString(), ClaimValueTypes.Integer64));

        foreach (var userRole in userRoles)
        {
            claims.Add(new Claim("role", userRole));
        }

        var identityClaims = new ClaimsIdentity();
        identityClaims.AddClaims(claims);

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_appSettings.Secret);

        var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _appSettings.Emissor,
            Audience = _appSettings.ValidoEm,
            Subject = identityClaims,
            Expires = DateTime.UtcNow.AddHours(_appSettings.ExpiracaoHoras),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)

        });

        var encodedToken = tokenHandler.WriteToken(token);

        return new LoginResponseViewModel
        {
            AccessToken = encodedToken,
            ExpiresIn = TimeSpan.FromHours(_appSettings.ExpiracaoHoras).TotalSeconds,
            UserToken = new UserTokenViewModel
            {
                Id = user.Id,
                Email = user.Email!,
                Claims = claims.Select(c => new ClaimViewModel { Type = c.Type, Value = c.Value })
            }
        };
    }

    private static long ToUnixEpochDate(DateTime date)
    {
        return (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
    }
}