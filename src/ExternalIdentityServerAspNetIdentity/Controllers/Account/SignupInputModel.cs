using System.ComponentModel.DataAnnotations;

namespace ExternalIdentityServerAspNetIdentity.Controllers.Account
{
    public class SignupInputModel
    {
        [Required]
        public string Email { get; set; }
        public string Base64ReturnUrl { get; set; }
    }
}