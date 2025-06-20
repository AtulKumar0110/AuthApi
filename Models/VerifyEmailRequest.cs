using System.ComponentModel.DataAnnotations;

namespace AuthApi.Models
{
    public class VerifyEmailRequest
    {
        [Required]
        public string Email { get; set; }

        [Required]
        public string Token { get; set; }
    }
}
