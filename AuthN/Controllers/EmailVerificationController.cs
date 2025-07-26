using AuthApi.Data;
using AuthApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
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
        private readonly ILogger<EmailVerificationController> _logger;

        public EmailVerificationController(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            ILogger<EmailVerificationController> logger)
        {
            _context = context;
            _userManager = userManager;
            _logger = logger;
        }

        [HttpGet("verify")]
        public async Task<IActionResult> VerifyEmail([FromQuery] string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                _logger.LogWarning("Email verification failed: empty token received.");
                return Content("<h2 style='color:red;'>Token is required.</h2>", "text/html");
            }

            var tokenHash = HashToken(token);

            var verification = await _context.EmailVerificationTokens
                .Include(v => v.User)
                .FirstOrDefaultAsync(v =>
                    v.TokenHash == tokenHash &&
                    !v.IsUsed &&
                    v.ExpiryTime > DateTime.UtcNow);

            if (verification == null)
            {
                _logger.LogWarning("Email verification failed: invalid or expired token.");
                return Content("<h2 style='color:red;'>Invalid or expired token.</h2>", "text/html");
            }

            verification.IsUsed = true;
            verification.User.EmailConfirmed = true;

            try
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Email verified successfully for user {UserId}.", verification.UserId);

                // ✅ Return friendly HTML success message
                return Content("<h2 style='color:green;'>✅ Email verified successfully! You may now log in.</h2>", "text/html");

                // 🔁 Or redirect to your frontend (uncomment below)
                // return Redirect("https://your-frontend-site.com/verified-success");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while verifying email for user {UserId}.", verification.UserId);
                return Content("<h2 style='color:red;'>An error occurred while verifying your email. Please try again later.</h2>", "text/html");
            }
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
