using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthApi.Data;
using AuthApi.Models;
using Microsoft.IdentityModel.Tokens;
using AuthApi.Services;

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
                var roleResult = await _roleManager.CreateAsync(new IdentityRole(model.Role));
                if (!roleResult.Succeeded)
                    return BadRequest("Failed to create role.");
            }

            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email
            };

            var createResult = await _userManager.CreateAsync(user, model.Password);
            if (!createResult.Succeeded)
            {
                var errors = createResult.Errors.Select(e => e.Description);
                return BadRequest(new { Errors = errors });
            }

            await _userManager.AddToRoleAsync(user, model.Role);

            // ✅ Generate and send verification email
            var token = GenerateEmailVerificationToken();
            var tokenHash = HashToken(token);

            var verification = new EmailVerificationToken
            {
                TokenHash = tokenHash,
                ExpiryTime = DateTime.UtcNow.AddHours(24),
                UserId = user.Id
            };

            _context.EmailVerificationTokens.Add(verification);
            await _context.SaveChangesAsync();

            await _emailService.SendVerificationEmail(user.Email, token);

            return Ok(new { Message = "User registered successfully. Verification email sent." });
        }


        [HttpGet("verify-email")]
public async Task<IActionResult> VerifyEmail([FromQuery] string token)
{
    if (string.IsNullOrEmpty(token))
        return BadRequest("Token is required.");

    var tokenHash = HashToken(token);

    var verification = await _context.EmailVerificationTokens
        .Include(t => t.User)
        .FirstOrDefaultAsync(t => t.TokenHash == tokenHash && !t.IsUsed);

    if (verification == null || verification.ExpiryTime < DateTime.UtcNow)
        return BadRequest("Invalid or expired token.");

    verification.IsUsed = true;

    verification.User.EmailConfirmed = true; // Mark email as verified
    _context.EmailVerificationTokens.Update(verification);
    _context.Users.Update(verification.User);

    await _context.SaveChangesAsync();

    return Ok("Email verified successfully.");
}


        [HttpPost("login")]
     public async Task<IActionResult> Login(LoginModel model)
{
    if (!ModelState.IsValid)
        return BadRequest(ModelState);

    var user = await _userManager.FindByEmailAsync(model.Email);
    if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
        return Unauthorized("Invalid credentials.");

    // ✅ Block login if email not confirmed
    if (!user.EmailConfirmed)
        return Unauthorized("Please verify your email before logging in.");

    var authClaims = await GetClaimsAsync(user);
    var accessToken = GenerateAccessToken(authClaims);
    var refreshToken = GenerateRefreshToken();
    var hashedToken = HashToken(refreshToken);

    var refreshEntity = new RefreshToken
    {
        TokenHash = hashedToken,
        ExpiryTime = DateTime.UtcNow.AddDays(7),
        UserId = user.Id
    };

    _context.RefreshTokens.Add(refreshEntity);
    await _context.SaveChangesAsync();

    return Ok(new TokenModel
    {
        AccessToken = accessToken,
        RefreshToken = refreshToken
    });
}


        [HttpPost("refresh-token")]
        public async Task<IActionResult> Refresh(TokenModel tokenModel)
        {
            if (tokenModel is null)
                return BadRequest("Invalid client request");

            var principal = GetPrincipalFromExpiredToken(tokenModel.AccessToken);
            var username = principal.Identity?.Name;

            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
                return Unauthorized("Invalid access");

            var hashedRefreshToken = HashToken(tokenModel.RefreshToken);

            var storedToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.UserId == user.Id && rt.TokenHash == hashedRefreshToken && !rt.IsRevoked);

            if (storedToken == null || storedToken.ExpiryTime <= DateTime.UtcNow)
                return BadRequest("Invalid or expired refresh token");

            storedToken.IsRevoked = true;

            var newRefreshToken = GenerateRefreshToken();
            var newTokenEntry = new RefreshToken
            {
                TokenHash = HashToken(newRefreshToken),
                ExpiryTime = DateTime.UtcNow.AddDays(7),
                UserId = user.Id
            };

            _context.RefreshTokens.Add(newTokenEntry);
            await _context.SaveChangesAsync();

            var newAccessToken = GenerateAccessToken(principal.Claims.ToList());

            return Ok(new TokenModel
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var user = await _userManager.FindByNameAsync(User.Identity?.Name);
            if (user == null)
                return Unauthorized("User not found.");

            var tokens = _context.RefreshTokens.Where(rt => rt.UserId == user.Id && !rt.IsRevoked);
            foreach (var token in tokens)
            {
                token.IsRevoked = true;
            }

            await _context.SaveChangesAsync();
            return Ok(new { Message = "User logged out successfully." });
        }

        // 🔒 Helper Methods
        private async Task<List<Claim>> GetClaimsAsync(ApplicationUser user)
        {
            var roles = await _userManager.GetRolesAsync(user);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
            return claims;
        }

        private string GenerateAccessToken(List<Claim> claims)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Issuer"],
                expires: DateTime.UtcNow.AddMinutes(15),
                claims: claims,
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private string GenerateEmailVerificationToken()
        {
            var randomBytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }

        private string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(token);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

            if (securityToken is not JwtSecurityToken jwtToken ||
                !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }
    }

    // Models
    public class RegisterModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [MinLength(6)]
        public string Password { get; set; }

        [Required]
        public string Role { get; set; }
    }

    public class LoginModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }

    public class TokenModel
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }
}
