using System.ComponentModel.DataAnnotations;

namespace IdentityServerHost.Quickstart.UI
{
    public class SignupInputModel
    {
        [Required]
        public string Email { get; set; }
        public string Base64ReturnUrl { get; set; }
    }
}