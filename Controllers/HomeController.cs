using Microsoft.AspNetCore.Mvc;

namespace _0AuthLogin.Controllers
{
    [ApiController]
    [Route("")]
    public class HomeController : ControllerBase
    {
        [HttpGet("")]
        public IActionResult RedirectToAuth()
        {
            return Redirect("/auth");
        }
    }
}
