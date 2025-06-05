using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthApi.Models
{
    public class ApplicationUser : IdentityUser
    {
        // ✅ Hashed refresh token (legacy support or fallback)
        public string? RefreshTokenHash { get; set; }

        // ✅ Optional expiration for the refresh token
        public DateTime? RefreshTokenExpiryTime { get; set; }

        // ✅ Email verification flag
        public bool IsEmailVerified { get; set; } = false;

        // ✅ Future scalability: support multiple refresh tokens (multi-device)
        public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();

        // ✅ Track email verification tokens
        public ICollection<EmailVerificationToken> EmailVerificationTokens { get; set; } = new List<EmailVerificationToken>();
    }
}
