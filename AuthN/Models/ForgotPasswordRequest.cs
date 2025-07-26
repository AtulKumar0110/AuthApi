using System.ComponentModel.DataAnnotations;

namespace AuthApi.Models
{
    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
