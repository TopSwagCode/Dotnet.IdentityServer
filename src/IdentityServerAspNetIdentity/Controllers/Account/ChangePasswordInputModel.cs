namespace IdentityServerAspNetIdentity.Controllers.Account
{
    public class ChangePasswordInputModel
    {
        public string CurrentPassword { get; set; }
        public string NewPassword { get; set; }
    }
}