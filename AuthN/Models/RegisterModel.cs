using System.ComponentModel.DataAnnotations;

namespace AuthApi.Models
{
    public class RegisterModelFixed
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string PhoneNumber { get; set; }  // ✅ Make sure this line exists

        [Required]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters")]
        public string Password { get; set; }

        [Required]
        public string Role { get; set; }
    }
}
