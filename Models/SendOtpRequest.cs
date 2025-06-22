using System.ComponentModel.DataAnnotations;

public class SendOtpRequest
{
    [Required]
    public string PhoneNumber { get; set; }
}
