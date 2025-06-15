using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using AuthApi.Models; // Adjust if ApplicationUser is elsewhere

namespace AuthApi.Entities // Adjust to your namespace
{
    public class PasswordResetToken
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string TokenHash { get; set; }

        [Required]
        public DateTime ExpiryTime { get; set; }

        [Required]
        public string UserId { get; set; }

        [ForeignKey(nameof(UserId))]
        public ApplicationUser User { get; set; }

        public bool IsUsed { get; set; } = false;
    }
}
