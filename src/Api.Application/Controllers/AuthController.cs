using Api.Domain.Entities;
using Api.Domain.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Api.Application.Controllers;

[ApiController]
[Route("api")]
public class AuthController : ControllerBase
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;

    public AuthController(
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager
    )
    {
        _signInManager = signInManager;
        _userManager = userManager;
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
            return Ok(new RespostaEntity(true, msg));
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
            return Ok(new RespostaEntity(true, msg));
        }

        if (result.IsLockedOut)
        {
            msg = "Usuário temporariamente bloqueado por tentativas inválidas";
            return BadRequest(new RespostaEntity(false, msg));
        }

        msg = "Usúario ou senha inválidos";
        return BadRequest(new RespostaEntity(false, msg));
    }
}