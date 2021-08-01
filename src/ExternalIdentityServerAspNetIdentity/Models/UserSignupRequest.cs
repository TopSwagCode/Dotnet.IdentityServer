using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ExternalIdentityServerAspNetIdentity.Models
{
    public class UserSignupRequest
    {
        public Guid EmailValidationToken { get; set; }
        public string Email { get; set; }
        public bool IsEmailValidationTokenUsed { get; set; }
        public DateTimeOffset ExpireOnUtc { get; set; }
    }
}
