// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.ComponentModel.DataAnnotations;

namespace IdentityServerHost.Quickstart.UI
{
    public class LoginInputModel
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
        public bool RememberLogin { get; set; }
        public string ReturnUrl { get; set; }
    }

    public class SignupInputModel
    {
        [Required]
        public string Email { get; set; }
    }

    public class CreateUserInputModel
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
        [Required]
        public string PasswordRepeat { get; set; }
        [Required]
        public string Email { get; set; }
        public Guid? EmailValidationToken { get; set; }
    }

    public class CreateUserViewModel : CreateUserInputModel
    {

    }
}