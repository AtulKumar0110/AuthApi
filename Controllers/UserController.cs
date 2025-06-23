using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        // Accessible to any authenticated user
        [Authorize]
        [HttpGet("me")]
        public IActionResult GetProfile()
        {
            return Ok("Hello, authenticated user!");
        }

        // Accessible only to users with the 'Admin' role
        [Authorize(Roles = "Admin")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnly()
        {
            return Ok("Hello, Admin!");
        }

        // Accessible to Admin or Manager
        [Authorize(Roles = "Admin,Manager")]
        [HttpGet("admin-or-manager")]
        public IActionResult AdminOrManager()
        {
            return Ok("Hello, Admin or Manager!");
        }
    }
}
