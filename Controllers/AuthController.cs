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
        private readonly IConfiguration _config;

        private readonly ISmsService _smsService;

        public AuthController(
      UserManager<ApplicationUser> userManager,
      RoleManager<IdentityRole> roleManager,
      IConfiguration config,
      ApplicationDbContext context,
      IEmailService emailService,
      ISmsService smsService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _config = config;
            _context = context;
            _emailService = emailService;
            _smsService = smsService;
        }



        // 🟢 Register
        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterModelFixed model)
        {

            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
                return BadRequest("User with this email already exists.");

            if (!await _roleManager.RoleExistsAsync(model.Role))
                await _roleManager.CreateAsync(new IdentityRole(model.Role));

            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                PhoneNumber = model.PhoneNumber,
                EmailConfirmed = false,
                PhoneVerified = false
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return BadRequest(result.Errors.Select(e => e.Description));

            await _userManager.AddToRoleAsync(user, model.Role);

            // Generate and store email verification token
            var emailToken = GenerateSecureToken();
            var emailTokenHash = HashToken(emailToken);

            _context.EmailVerificationTokens.Add(new EmailVerificationToken
            {
                TokenHash = emailTokenHash,
                ExpiryTime = DateTime.UtcNow.AddHours(24),
                UserId = user.Id
            });

            // Generate and store phone verification OTP
            var phoneOtp = new Random().Next(100000, 999999).ToString();

            _context.PhoneVerificationTokens.Add(new PhoneVerificationToken
            {
                Token = phoneOtp,
                ExpiryTime = DateTime.UtcNow.AddMinutes(10),
                UserId = user.Id
            });

            await _context.SaveChangesAsync();

            // Send verification emails/SMS
            await _emailService.SendVerificationEmail(user.Email, emailToken);
            await _emailService.SendAsync(user.Email, "Phone Verification OTP", $"Your OTP is: {phoneOtp}");

            return Ok("Registration successful. Check your email and SMS to verify.");
        }


        // 🟢 Verify Email
        [HttpPost("verify-email")]
        public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailRequest model)
        {
            if (string.IsNullOrWhiteSpace(model.Token))
                return BadRequest("Token is required.");

            var tokenHash = HashToken(model.Token);

            var verification = await _context.EmailVerificationTokens
                .Include(v => v.User)
                .FirstOrDefaultAsync(v =>
                    v.TokenHash == tokenHash &&
                    !v.User.EmailConfirmed &&
                    v.ExpiryTime > DateTime.UtcNow);

            if (verification == null)
                return BadRequest("Invalid or expired token.");

            var user = verification.User;
            user.EmailConfirmed = true;

            _context.EmailVerificationTokens.Remove(verification);

            await _context.SaveChangesAsync();

            // Optional: Log or send confirmation message
            // _logger.LogInformation($"User {user.Email} email verified.");

            return Ok("Email verified successfully.");
        }


        // 🟢 Verify Phone
        [HttpPost("verify-phone")]
        public async Task<IActionResult> VerifyPhone([FromBody] VerifyPhoneRequest model)
        {
            if (string.IsNullOrWhiteSpace(model.Otp))
                return BadRequest("OTP is required.");

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return BadRequest("User not found.");

            var verification = await _context.PhoneVerificationTokens
                .FirstOrDefaultAsync(p =>
                    p.UserId == user.Id &&
                    p.Token == model.Otp &&
                    p.ExpiryTime > DateTime.UtcNow);

            if (verification == null)
                return BadRequest("Invalid or expired OTP.");

            user.PhoneVerified = true;

            _context.PhoneVerificationTokens.Remove(verification);
            await _userManager.UpdateAsync(user); // 🟢 Save PhoneVerified flag to DB
            await _context.SaveChangesAsync();

            return Ok("Phone number verified successfully.");
        }

        [HttpPost("send-otp")]
        public async Task<IActionResult> SendOtp([FromBody] SendOtpRequest model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.Users
                .FirstOrDefaultAsync(u => u.PhoneNumber == model.PhoneNumber);

            if (user == null)
                return BadRequest("User not found.");

            var otp = GenerateOtp();

            // Optionally store hashed OTP in DB for verification later
            // var hashedOtp = HashToken(otp);

            await _smsService.SendAsync(user.PhoneNumber, $"Your OTP is: {otp}");

            return Ok("OTP sent successfully.");
        }

        private string GenerateOtp()
        {
            var random = new Random();
            return random.Next(100000, 999999).ToString(); // Generates a 6-digit OTP
        }


        // 🟢 Login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // Try to find user by email or phone number
            var user = await _userManager.Users
                .FirstOrDefaultAsync(u =>
                    u.Email == model.EmailOrPhone || u.PhoneNumber == model.EmailOrPhone);

            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized("Invalid email/phone or password.");

            if (!user.EmailConfirmed)
                return Unauthorized("Please verify your email.");

            if (!user.PhoneVerified)
                return Unauthorized("Please verify your phone number.");

            var claims = await GetClaimsAsync(user);
            var accessToken = GenerateAccessToken(claims);
            var refreshToken = GenerateRefreshToken();
            var hashedRefreshToken = HashToken(refreshToken);

            _context.RefreshTokens.Add(new RefreshToken
            {
                TokenHash = hashedRefreshToken,
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

        // [HttpPost("refresh-token")]
        // public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest model)
        // {
        //     if (string.IsNullOrEmpty(model.RefreshToken))
        //         return BadRequest("Refresh token is required.");

        //     var hashedToken = HashToken(model.RefreshToken);
        //     var tokenEntity = await _context.RefreshTokens
        //         .Include(t => t.User)
        //         .FirstOrDefaultAsync(t =>
        //             t.TokenHash == hashedToken &&
        //             t.ExpiryTime > DateTime.UtcNow);

        //     if (tokenEntity == null)
        //         return Unauthorized("Invalid or expired refresh token.");

        //     var user = tokenEntity.User;
        //     var newAccessToken = GenerateAccessToken(await GetClaimsAsync(user));
        //     var newRefreshToken = GenerateRefreshToken();
        //     var newRefreshTokenHash = HashToken(newRefreshToken);

        //     // Store new refresh token and remove the old one
        //     _context.RefreshTokens.Remove(tokenEntity);
        //     _context.RefreshTokens.Add(new RefreshToken
        //     {
        //         TokenHash = newRefreshTokenHash,
        //         ExpiryTime = DateTime.UtcNow.AddDays(7),
        //         UserId = user.Id
        //     });

        //     await _context.SaveChangesAsync();

        //     return Ok(new TokenModel
        //     {
        //         AccessToken = newAccessToken,
        //         RefreshToken = newRefreshToken
        //     });
        // }



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

        [HttpPost("send-phone-otp")]
        public async Task<IActionResult> SendPhoneOtp([FromBody] string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null || string.IsNullOrEmpty(user.PhoneNumber))
                return BadRequest("User not found or phone number missing.");

            var code = new Random().Next(100000, 999999).ToString();
            var token = new PhoneVerificationToken
            {
                Code = code,
                UserId = user.Id,
                ExpiryTime = DateTime.UtcNow.AddMinutes(10)
            };

            _context.PhoneVerificationTokens.Add(token);
            await _context.SaveChangesAsync();

            // Simulate sending SMS
            Console.WriteLine($"[SIMULATED SMS] OTP for {user.PhoneNumber}: {code}");

            return Ok("OTP sent.");
        }


        [HttpPost("verify-phone-otp")]
        public async Task<IActionResult> VerifyPhoneOtp([FromBody] VerifyPhoneOtpRequest model)
        {
            var otpHash = HashToken(model.Otp);

            var entry = await _context.OtpEntries
                .FirstOrDefaultAsync(o => o.PhoneNumber == model.PhoneNumber && o.OtpHash == otpHash && !o.IsUsed && o.ExpiryTime > DateTime.UtcNow);

            if (entry == null)
                return BadRequest("Invalid or expired OTP.");

            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.PhoneNumber == model.PhoneNumber);
            if (user == null)
                return BadRequest("User not found.");

            // ✅ Use built-in Identity property for confirmation
            user.PhoneNumberConfirmed = true;
            entry.IsUsed = true;

            await _userManager.UpdateAsync(user);
            await _context.SaveChangesAsync();

            return Ok("Phone number verified successfully.");
        }


        [HttpPost("verify-phone-otp")]
        public async Task<IActionResult> VerifyPhoneOtp([FromBody] VerifyOtpRequest request)
        {
            var token = await _context.PhoneVerificationTokens
                .Where(t => t.UserId == request.UserId && t.Code == request.Code && !t.IsUsed && t.ExpiryTime > DateTime.UtcNow)
                .OrderByDescending(t => t.ExpiryTime)
                .FirstOrDefaultAsync();

            if (token == null)
                return BadRequest("Invalid or expired OTP.");

            var user = await _userManager.FindByIdAsync(request.UserId);
            if (user == null)
                return NotFound("User not found.");

            user.PhoneVerified = true;
            token.IsUsed = true;

            _context.PhoneVerificationTokens.Update(token);
            await _userManager.UpdateAsync(user);
            await _context.SaveChangesAsync();

            return Ok("Phone verified successfully.");
        }

        // private async Task<List<Claim>> GetClaimsAsync(ApplicationUser user)
        // {
        //     var roles = await _userManager.GetRolesAsync(user);
        //     var claims = new List<Claim>
        //     {
        //         new Claim(ClaimTypes.NameIdentifier, user.Id),
        //         new Claim(ClaimTypes.Name, user.UserName),
        //         new Claim(ClaimTypes.Email, user.Email ?? ""),
        //         new Claim("PhoneVerified", user.PhoneVerified.ToString())
        //     };

        //     claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
        //     return claims;
        // }


        private async Task<List<Claim>> GetClaimsAsync(ApplicationUser user)
        {
            var roles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id),
        new Claim(ClaimTypes.Name, user.UserName),
        new Claim(ClaimTypes.Email, user.Email ?? ""),
        new Claim("PhoneVerified", user.PhoneVerified.ToString()),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            return claims;
        }


        private string GenerateAccessToken(IEnumerable<Claim> claims)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
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
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return Ok("If an account exists, a password reset link will be sent."); // Prevent enumeration

            var token = GenerateSecureToken();
            var tokenHash = HashToken(token);

            _context.PasswordResetTokens.Add(new PasswordResetToken
            {
                TokenHash = tokenHash,
                ExpiryTime = DateTime.UtcNow.AddHours(1),
                UserId = user.Id
            });

            await _context.SaveChangesAsync();
            await _emailService.SendAsync(user.Email, "Password Reset", $"Your reset token: {token}");

            return Ok("Password reset link sent.");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest model)
        {
            var tokenHash = HashToken(model.Token);
            var resetEntry = await _context.PasswordResetTokens
                .Include(r => r.User)
                .FirstOrDefaultAsync(r =>
                    r.TokenHash == tokenHash &&
                    r.ExpiryTime > DateTime.UtcNow &&
                    !r.IsUsed);

            if (resetEntry == null)
                return BadRequest("Invalid or expired token.");

            var user = resetEntry.User;

            // Remove old password (optional, only needed if no reset functionality is available)
            var removeResult = await _userManager.RemovePasswordAsync(user);
            if (!removeResult.Succeeded)
                return BadRequest(removeResult.Errors);

            // Add new password
            var addResult = await _userManager.AddPasswordAsync(user, model.NewPassword);
            if (!addResult.Succeeded)
                return BadRequest(addResult.Errors);

            // Mark token as used instead of deleting
            resetEntry.IsUsed = true;
            await _context.SaveChangesAsync();

            return Ok("Password has been reset successfully.");
        }
        [HttpPost("phone-login")]
        public async Task<IActionResult> PhoneLogin([FromBody] VerifyPhoneOtpRequest model)
        {
            var otpHash = HashToken(model.Otp);

            var entry = await _context.OtpEntries
                .FirstOrDefaultAsync(o => o.PhoneNumber == model.PhoneNumber && o.OtpHash == otpHash && !o.IsUsed && o.ExpiryTime > DateTime.UtcNow);

            if (entry == null)
                return BadRequest("Invalid or expired OTP.");

            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.PhoneNumber == model.PhoneNumber);
            if (user == null)
                return Unauthorized("User not found.");

            // Mark OTP as used
            entry.IsUsed = true;
            await _context.SaveChangesAsync();

            // Generate JWT
            var claims = await GetClaimsAsync(user);
            var accessToken = GenerateAccessToken(claims);
            var refreshToken = GenerateRefreshToken();
            var hashedRefreshToken = HashToken(refreshToken);

            _context.RefreshTokens.Add(new RefreshToken
            {
                TokenHash = hashedRefreshToken,
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



        [HttpPost("resend-email-verification")]
        public async Task<IActionResult> ResendEmailVerification([FromBody] EmailOnlyRequest model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || user.EmailConfirmed)
                return Ok("If your email is not verified, a new link will be sent."); // Prevent email enumeration

            var token = GenerateSecureToken();
            var tokenHash = HashToken(token);

            _context.EmailVerificationTokens.Add(new EmailVerificationToken
            {
                TokenHash = tokenHash,
                ExpiryTime = DateTime.UtcNow.AddHours(1),
                UserId = user.Id
            });

            await _context.SaveChangesAsync();
            await _emailService.SendAsync(user.Email, "Verify Your Email", $"Verification code: {token}");

            return Ok("Verification email sent.");
        }

        [HttpPost("resend-phone-verification")]
        public async Task<IActionResult> ResendPhoneVerification([FromBody] EmailOnlyRequest model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || user.PhoneVerified)
                return Ok("If your phone is not verified, a new OTP will be sent.");

            var otp = new Random().Next(100000, 999999).ToString();
            _context.PhoneVerificationTokens.Add(new PhoneVerificationToken
            {
                Token = otp,
                ExpiryTime = DateTime.UtcNow.AddMinutes(5),
                UserId = user.Id
            });

            await _context.SaveChangesAsync();
            await _smsService.SendAsync(user.PhoneNumber, $"Your verification code is: {otp}");

            return Ok("OTP sent to your phone.");
        }


        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var hashedToken = HashToken(model.RefreshToken);
            var refreshToken = await _context.RefreshTokens
                .Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.TokenHash == hashedToken && rt.ExpiryTime > DateTime.UtcNow);

            if (refreshToken == null)
                return Unauthorized("Invalid or expired refresh token.");

            var user = refreshToken.User;
            var claims = await GetClaimsAsync(user);
            var newAccessToken = GenerateAccessToken(claims);
            var newRefreshToken = GenerateRefreshToken();
            var newHashedRefreshToken = HashToken(newRefreshToken);

            // Remove old token, add new one
            _context.RefreshTokens.Remove(refreshToken);
            _context.RefreshTokens.Add(new RefreshToken
            {
                TokenHash = newHashedRefreshToken,
                ExpiryTime = DateTime.UtcNow.AddDays(7),
                UserId = user.Id
            });

            await _context.SaveChangesAsync();

            return Ok(new TokenModel
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }



        // 🔧 Helpers
        // private async Task<List<Claim>> GetClaimsAsync(ApplicationUser user)
        // {
        //     var roles = await _userManager.GetRolesAsync(user);
        //     var claims = new List<Claim>
        //     {
        //         new Claim(ClaimTypes.Name, user.UserName),
        //         new Claim(ClaimTypes.NameIdentifier, user.Id),
        //         new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        //     };
        //     claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
        //     return claims;
        // }

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
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }



        // private string GenerateSecureToken()
        // {
        //     var bytes = new byte[32];
        //     using var rng = RandomNumberGenerator.Create();
        //     rng.GetBytes(bytes);
        //     return Convert.ToBase64String(bytes);
        // }
        private string GenerateSecureToken()
        {
            var bytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }


        // private string HashToken(string token)
        // {
        //     using var sha256 = SHA256.Create();
        //     var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
        //     return Convert.ToBase64String(hash);
        // }

        private string HashToken(string token)
        {
            // Create a SHA256 hash of the input token and convert to Base64
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(token);
            var hash = sha256.ComputeHash(bytes);
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
