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
    }
}
