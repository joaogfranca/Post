using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using SalesWebMvcCs.Models; // Certifique-se de incluir o namespace correto para o modelo de usuário

public class AccountController : Controller
{
    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        // Verificação básica de usuário e senha (substitua por uma autenticação adequada)
        if (IsValidUser(model.Username, model.Password))
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, model.Username),
                new Claim(ClaimTypes.Role, "User") // Adicione mais papéis conforme necessário
            };

            var claimsIdentity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var authProperties = new AuthenticationProperties
            {
                // Personalize as propriedades conforme necessário, por exemplo, definindo a expiração do cookie
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);

            return RedirectToAction("Index", "Departments");
        }

        // Login inválido
        ViewBag.ErrorMessage = "Credenciais inválidas.";
        return View();
    }

    [HttpGet]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Index", "Departments");
    }

    [HttpGet]
    public IActionResult AccessDenied()
    {
        return View();
    }

    private bool IsValidUser(string username, string password)
    {
        // Implemente a lógica de verificação de usuário e senha aqui
        // Pode ser uma consulta ao banco de dados ou outra forma de autenticação
        return username == "usuario" && password == "senha";
    }
}
