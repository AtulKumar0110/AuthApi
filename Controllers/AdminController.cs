using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers
{
    [Authorize(Roles = "Admin")]
    [Route("api/admin")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        [HttpGet("users")]
        public IActionResult GetAllUsers()
        {
            return Ok("Only Admins can see this");
        }

        [HttpGet("admin-only")]
        public IActionResult AdminEndpoint()
        {
            return Ok("This is protected and only accessible by Admins.");
        }

        [Authorize(Roles = "Admin,Manager")]
        [HttpGet("admin-or-manager")]
        public IActionResult AdminOrManagerEndpoint()
        {
            return Ok("This is for Admin or Manager roles.");
        }
    }
}
