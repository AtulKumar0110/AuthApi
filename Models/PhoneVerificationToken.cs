using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthApi.Models
{
    public class PhoneVerificationToken
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string Code { get; set; } // Example: 6-digit OTP like "123456"

        [Required]
        public DateTime ExpiryTime { get; set; }

        [Required]
        public string UserId { get; set; }

        [ForeignKey(nameof(UserId))]
        public ApplicationUser User { get; set; }

        public bool IsUsed { get; set; } = false;
    }
}
