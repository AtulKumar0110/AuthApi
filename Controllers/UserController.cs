using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers
{
    [Authorize(Roles = "User")]
    [Route("api/user")]
    [ApiController]
    public class UserController : ControllerBase
    {
        [HttpGet("profile")]
        public IActionResult GetProfile()
        {
            return Ok("This is user profile data");
        }
    }
}
