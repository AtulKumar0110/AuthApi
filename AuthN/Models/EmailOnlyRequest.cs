using System.ComponentModel.DataAnnotations;

namespace AuthApi.Models
{
    public class EmailOnlyRequest
    {
        [Required]
        public string Email { get; set; }
    }
}
