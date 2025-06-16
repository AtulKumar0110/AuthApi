using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthApi.Data;
using AuthApi.Models;
using AuthApi.Services;
using AuthApi.Entities;

namespace AuthApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;
        private readonly IEmailService _emailService;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            ApplicationDbContext context,
            IEmailService emailService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _context = context;
            _emailService = emailService;
        }

        // 🟢 Register
        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
                return BadRequest("User with this email already exists.");

            if (!await _roleManager.RoleExistsAsync(model.Role))
            {
                await _roleManager.CreateAsync(new IdentityRole(model.Role));
            }

            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return BadRequest(result.Errors.Select(e => e.Description));

            await _userManager.AddToRoleAsync(user, model.Role);

            var token = GenerateSecureToken();
            var hashed = HashToken(token);

            _context.EmailVerificationTokens.Add(new EmailVerificationToken
            {
                TokenHash = hashed,
                ExpiryTime = DateTime.UtcNow.AddHours(24),
                UserId = user.Id
            });

            await _context.SaveChangesAsync();
            await _emailService.SendVerificationEmail(user.Email, token);

            return Ok("Registration successful. Please check your email to verify.");
        }

        // 🟢 Resend Verification
        [HttpPost("resend-verification")]
        public async Task<IActionResult> ResendVerificationEmail([FromBody] ResendVerificationRequest model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || user.EmailConfirmed)
                return BadRequest("Invalid request.");

            var token = GenerateSecureToken();
            var hashed = HashToken(token);

            _context.EmailVerificationTokens.Add(new EmailVerificationToken
            {
                TokenHash = hashed,
                ExpiryTime = DateTime.UtcNow.AddHours(24),
                UserId = user.Id
            });

            await _context.SaveChangesAsync();
            await _emailService.SendVerificationEmail(user.Email, token);

            return Ok("Verification email resent.");
        }

        // 🟢 Verify Email
        [HttpPost("verify-email")]
        public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailRequest model)
        {
            var hash = HashToken(model.Token);
            var verification = await _context.EmailVerificationTokens
                .Include(v => v.User)
                .FirstOrDefaultAsync(v => v.TokenHash == hash && !v.User.EmailConfirmed);

            if (verification == null || verification.ExpiryTime < DateTime.UtcNow)
                return BadRequest("Invalid or expired token.");

            verification.User.EmailConfirmed = true;
            _context.EmailVerificationTokens.Remove(verification);
            await _context.SaveChangesAsync();

            return Ok("Email verified successfully.");
        }

        // 🟢 Login
        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized("Invalid credentials.");

            if (!user.EmailConfirmed)
                return Unauthorized("Please verify your email first.");

            var claims = await GetClaimsAsync(user);
            var accessToken = GenerateAccessToken(claims);
            var refreshToken = GenerateRefreshToken();

            var hashed = HashToken(refreshToken);

            _context.RefreshTokens.Add(new RefreshToken
            {
                TokenHash = hashed,
                ExpiryTime = DateTime.UtcNow.AddDays(7),
                UserId = user.Id
            });

            await _context.SaveChangesAsync();

            return Ok(new TokenModel
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });
        }

        // 🔁 Refresh Token
        [HttpPost("refresh-token")]
        public async Task<IActionResult> Refresh([FromBody] TokenModel tokenModel)
        {
            if (tokenModel is null || string.IsNullOrEmpty(tokenModel.RefreshToken))
                return BadRequest("Missing refresh token.");

            var principal = GetPrincipalFromExpiredToken(tokenModel.AccessToken);
            var username = principal.Identity?.Name;

            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
                return Unauthorized("Invalid token.");

            var hashed = HashToken(tokenModel.RefreshToken);

            var stored = await _context.RefreshTokens.FirstOrDefaultAsync(t =>
                t.UserId == user.Id && t.TokenHash == hashed && !t.IsRevoked && t.ExpiryTime > DateTime.UtcNow);

            if (stored == null)
                return Unauthorized("Invalid or expired refresh token.");

            stored.IsRevoked = true;

            var newRefresh = GenerateRefreshToken();
            var newHashed = HashToken(newRefresh);

            _context.RefreshTokens.Add(new RefreshToken
            {
                TokenHash = newHashed,
                ExpiryTime = DateTime.UtcNow.AddDays(7),
                UserId = user.Id
            });

            await _context.SaveChangesAsync();

            return Ok(new TokenModel
            {
                AccessToken = GenerateAccessToken(principal.Claims.ToList()),
                RefreshToken = newRefresh
            });
        }

        // 🚪 Logout
        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var user = await _userManager.FindByNameAsync(User.Identity.Name);
            if (user == null) return Unauthorized();

            var tokens = _context.RefreshTokens
                .Where(t => t.UserId == user.Id && !t.IsRevoked);
            foreach (var t in tokens)
                t.IsRevoked = true;

            await _context.SaveChangesAsync();
            return Ok("Logged out successfully.");
        }

        // 🔐 Request Password Reset
        [HttpPost("request-password-reset")]
        public async Task<IActionResult> RequestPasswordReset([FromBody] RequestPasswordResetModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !user.EmailConfirmed)
                return Ok("If registered, a reset link has been sent.");

            var token = GenerateSecureToken();
            var hashed = HashToken(token);

            _context.PasswordResetTokens.Add(new PasswordResetToken
            {
                TokenHash = hashed,
                ExpiryTime = DateTime.UtcNow.AddHours(1),
                UserId = user.Id
            });

            await _context.SaveChangesAsync();
            await _emailService.SendPasswordResetEmail(user.Email, token);

            return Ok("If registered, a reset link has been sent.");
        }

        // 🔐 Reset Password
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null) return BadRequest("Invalid user or token.");

            var hash = HashToken(model.Token);
            var tokenEntry = await _context.PasswordResetTokens
                .FirstOrDefaultAsync(t => t.UserId == user.Id && t.TokenHash == hash && !t.IsUsed && t.ExpiryTime > DateTime.UtcNow);

            if (tokenEntry == null)
                return BadRequest("Invalid or expired token.");

            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, resetToken, model.NewPassword);

            if (!result.Succeeded)
                return BadRequest(result.Errors.Select(e => e.Description));

            tokenEntry.IsUsed = true;
            await _context.SaveChangesAsync();

            return Ok("Password reset successful.");
        }

        // 🔧 Helpers
        private async Task<List<Claim>> GetClaimsAsync(ApplicationUser user)
        {
            var roles = await _userManager.GetRolesAsync(user);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
            return claims;
        }

        private string GenerateAccessToken(List<Claim> claims)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Issuer"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateRefreshToken()
        {
            var random = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(random);
            return Convert.ToBase64String(random);
        }

        private string GenerateSecureToken()
        {
            var bytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        private string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(hash);
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParams = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]))
            };

            var principal = tokenHandler.ValidateToken(token, validationParams, out var securityToken);
            if (securityToken is not JwtSecurityToken jwt || !jwt.Header.Alg.Equals(SecurityAlgorithms.HmacSha256))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }
    }

    // ✅ DTOs

    public class RegisterModel
    {
        [Required, EmailAddress] public string Email { get; set; }
        [Required, MinLength(6)] public string Password { get; set; }
        [Required] public string Role { get; set; }
    }

    public class LoginModel
    {
        [Required, EmailAddress] public string Email { get; set; }
        [Required] public string Password { get; set; }
    }

    public class TokenModel
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }

    public class ResendVerificationRequest
    {
        [Required, EmailAddress] public string Email { get; set; }
    }

    public class VerifyEmailRequest
    {
        [Required] public string Token { get; set; }
    }

    public class RequestPasswordResetModel
    {
        [Required, EmailAddress] public string Email { get; set; }
    }

    public class ResetPasswordModel
    {
        [Required] public string Token { get; set; }
        [Required, EmailAddress] public string Email { get; set; }
        [Required, MinLength(6)] public string NewPassword { get; set; }
    }
}
