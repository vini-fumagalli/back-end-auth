using Api.Application.Controllers;
using Api.CrossCutting.Configuration;
using Api.Domain.Entities;
using Api.Domain.ViewModels;
using FakeItEasy;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Xunit;

namespace UnitTesting;

public class AuthTest
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IOptions<AppSettings> _appSettings;
    private readonly AuthController _authController;
    private readonly AuthController _token;

    public AuthTest()
    {
        _userManager = A.Fake<UserManager<IdentityUser>>();
        _signInManager = A.Fake<SignInManager<IdentityUser>>();
        _appSettings = A.Fake<IOptions<AppSettings>>();
        _token = A.Fake<AuthController>(t => t.CallsBaseMethods());
        _authController = new AuthController(_signInManager, _userManager, _appSettings);
    }

    [Fact]
    public async Task AuthController_SignUp_ReturnsOk()
    {
        //Arrange 
        var userViewModel = new RegisterUserViewModel
        {
            Email = "unit@testing.com",
            Password = "XUnit_Test",
            ConfirmPassword = "XUnit_Test"
        };

        var loginResponse = new LoginResponseViewModel
        {
            AccessToken = "TesteToken",
            ExpiresIn = 3600,
            UserToken = new UserTokenViewModel
            {
                Id = "Teste Id",
                Email = "email@teste",
                Claims = new List<ClaimViewModel>
                {
                    new() { Type = "Teste Type", Value = "Teste Value "}
                }
            }
        };

        var createResult = IdentityResult.Success;

        A.CallTo(() => _userManager.CreateAsync(A<IdentityUser>._, A<string>._)).Returns(Task.FromResult(createResult));

        //Act
        var result = await _authController.SignUp(userViewModel);

        //Assert
        var statusCode = Assert.IsType<OkObjectResult>(result.Result);
        statusCode.StatusCode.Should().Be(200);
    }

}
