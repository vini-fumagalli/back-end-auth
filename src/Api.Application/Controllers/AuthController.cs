using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Api.CrossCutting.Configuration;
using Api.Domain.Entities;
using Api.Domain.Interfaces.Repositories;
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
    private readonly ICodAutRepository _codAutRepository;

    public AuthController(
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IOptions<AppSettings> appSettings,
        ICodAutRepository codAutRepository
    )
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _appSettings = appSettings.Value;
        _codAutRepository = codAutRepository;
    }

    [HttpPost("sign-up")]
    public async Task<ActionResult<RespostaEntity>> SignUp(RegisterUserViewModel registerUser)
    {
        string msg;

        if (!ModelState.IsValid) return BadRequest();

        var user = await _userManager.FindByEmailAsync(registerUser.Email);
        if (user == null)
        {
            msg = "Esse usuário já existe no sistema";
            return Conflict(msg);
        }

        await _codAutRepository.GerarCodEnviarEmail(registerUser.Email);
        return Ok(new RespostaEntity
        {
            Sucesso = true,
            Mensagem = "Código de autenticação enviado no seu email"
        });
    }

    [HttpPost("cod-aut")]
    public async Task<ActionResult<RespostaEntity>> CodAut(CodAutViewModel vm)
    {
        string msg;

        if (!await _codAutRepository.CodigoValido(vm))
        {
            msg = "Código inválido";
            return NotFound(msg);
        }

        var user = new IdentityUser
        {
            UserName = vm.Email,
            Email = vm.Email,
            EmailConfirmed = true
        };

        var result = await _userManager.CreateAsync(user, vm.Password);
        if (result.Succeeded)
        {
            await _signInManager.SignInAsync(user, false);
            msg = "Usuário cadastrado e logado com sucesso";
            return Ok(new RespostaEntity(true, await GerarJwt(user.Email), msg));
        }

        msg = "Erro ao realizar cadastro de usuário";
        return BadRequest(msg);
    }

    [HttpPost("sign-in")]
    public async Task<ActionResult<RespostaEntity>> Login(LoginUserViewModel loginUser)
    {
        string msg;

        if (!ModelState.IsValid) return BadRequest();

        var result = await _signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, false, true);

        if (result.Succeeded)
        {
            msg = "Login realizado com sucesso";
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

    [ClaimsAuthorize("Administrador", "Poder Supremo")]
    [HttpGet("saudacao")]
    public ActionResult<RespostaEntity> Saudacao()
    {
        var data = "Olá, Você está autenticado :)";
        return Ok(new RespostaEntity(true, data));
    }

    public virtual async Task<LoginResponseViewModel> GerarJwt(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        var claims = await _userManager.GetClaimsAsync(user!);
        var userRoles = await _userManager.GetRolesAsync(user!);
        var userClaims = new List<Claim>(claims);

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
            ExpiresAt = DateTime.UtcNow.AddHours(_appSettings.ExpiracaoHoras).ToLocalTime(),
            UserToken = new UserTokenViewModel
            {
                Id = user.Id,
                Email = user.Email!,
                Claims = userClaims.Select(c => new ClaimViewModel { Type = c.Type, Value = c.Value })
            }
        };
    }

    private static long ToUnixEpochDate(DateTime date)
    {
        return (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
    }
}