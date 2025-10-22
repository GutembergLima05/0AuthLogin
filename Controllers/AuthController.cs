using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using _0AuthLogin.Models;

namespace _0AuthLogin.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly IConfiguration _configuration;

    public AuthController(ILogger<AuthController> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    /// <summary>
    /// Inicia o processo de login com Google
    /// </summary>
    [HttpGet("login")]
    public IActionResult Login(string returnUrl = "/")
    {
        var urlProd = _configuration["UrlProd"];
        
        var properties = new AuthenticationProperties
        {
            RedirectUri = urlProd
        };

        return Challenge(properties, GoogleDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// Retorna informações do usuário autenticado
    /// </summary>
    [Authorize]
    [HttpGet("user")]
    public IActionResult GetUser()
    {
        var claims = User.Claims;
        var userInfo = new UserInfo
        {
            Id = claims?.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value ?? "",
            Email = claims?.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value ?? "",
            Name = claims?.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value ?? "",
            Picture = claims?.FirstOrDefault(c => c.Type == "picture")?.Value ?? "",
            Provider = "Google"
        };

        return Ok(userInfo);
    }

    /// <summary>
    /// Realiza logout
    /// </summary>
    [Authorize]
    [HttpPost("logout")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Ok(new { message = "Logout realizado com sucesso" });
    }

    /// <summary>
    /// Verifica se o usuário está autenticado
    /// </summary>
    [HttpGet("status")]
    public IActionResult Status()
    {
        return Ok(new
        {
            isAuthenticated = User.Identity?.IsAuthenticated ?? false,
            name = User.Identity?.Name
        });
    }
}
