using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]  // Protect entire controller
    public class ProfileController : ControllerBase
    {   [Authorize]
        [HttpGet("me")]
        public IActionResult GetProfile()
        {
            // Access user info from claims
            var username = User.Identity.Name;
            return Ok(new { Message = $"Hello, {username}. This is your profile info." });
        }

        [HttpGet("adminonly")]
        [Authorize(Roles = "Admin")]  // Role-based protection
        public IActionResult AdminOnly()
        {
            return Ok("This is a protected Admin-only endpoint.");
        }
    }
}
