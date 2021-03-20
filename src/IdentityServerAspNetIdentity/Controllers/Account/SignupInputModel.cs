using System.ComponentModel.DataAnnotations;

namespace IdentityServerAspNetIdentity.Controllers.Account
{
    public class SignupInputModel
    {
        [Required]
        public string Email { get; set; }
        public string Base64ReturnUrl { get; set; }
    }
}