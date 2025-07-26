using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthApi.Models
{
    public class OtpEntry
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string PhoneNumber { get; set; }

        [Required]
        public string OtpHash { get; set; }

        [Required]
        public DateTime ExpiryTime { get; set; }

        public bool IsUsed { get; set; } = false;
    }
}
