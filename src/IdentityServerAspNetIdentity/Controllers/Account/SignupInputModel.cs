using System.ComponentModel.DataAnnotations;

namespace IdentityServerAspNetIdentity.Controllers.Account
{
    public class SignupInputModel
    {
        [Required]
        public string Email { get; set; }
        public string Base64ReturnUrl { get; set; }
    }

    public class DeleteUserInputModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class DeleteUserViewModel : DeleteUserInputModel
    {
        public bool IsLocalUser { get; set; }
    }
}