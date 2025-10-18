using Microsoft.AspNetCore.Mvc;

namespace _0AuthLogin.Controllers
{
    [ApiController]
    [Route("")]
    public class HomeController : ControllerBase
    {
        [HttpGet("")]
        public async Task<IActionResult> RedirectToAuth()
        {
            return Redirect("/auth");
        }
    }
}
