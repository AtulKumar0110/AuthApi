using System.ComponentModel.DataAnnotations;

namespace AuthApi.Models
{
    public class VerifyPhoneRequest
    {
        [Required]
        public string Email { get; set; }

        [Required]
        public string Otp { get; set; }
    }
}
