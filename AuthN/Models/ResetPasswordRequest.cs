using System.ComponentModel.DataAnnotations;

namespace AuthApi.Models
{
    public class ResetPasswordRequest
    {
        [Required]
        public string Token { get; set; }

        [Required]
        public string Email { get; set; }

        [Required]
        [MinLength(6)]
        public string NewPassword { get; set; }
    }
}
