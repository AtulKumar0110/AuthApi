using AuthApi.Data;
using AuthApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace AuthApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class EmailVerificationController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;

        public EmailVerificationController(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        [HttpGet("verify")]
        public async Task<IActionResult> VerifyEmail([FromQuery] string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return BadRequest("Token is required.");

            var tokenHash = HashToken(token);

            var verification = await _context.EmailVerificationTokens
                .Include(v => v.User)
                .FirstOrDefaultAsync(v => v.TokenHash == tokenHash && !v.IsUsed && v.ExpiryTime > DateTime.UtcNow);

            if (verification == null)
                return BadRequest("Invalid or expired token.");

            verification.IsUsed = true;
            verification.User.EmailConfirmed = true;

            await _context.SaveChangesAsync();

            return Ok(new { message = "Email verified successfully." });
        }

        private string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(token);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }
    }
}
