// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServerAspNetIdentity.Data;
using IdentityServerAspNetIdentity.Models;
using IdentityServerAspNetIdentity.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace IdentityServerAspNetIdentity.Controllers.Account
{
    /*
        foreach (var error in resetPassResult.Errors)
        {
            ModelState.TryAddModelError(error.Code, error.Description);
        }
     */

    [SecurityHeaders]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
        private readonly ApplicationDbContext _dbContext;
        private readonly IEmailService _emailService;
        private readonly ILogger<AccountController> _logger;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            ApplicationDbContext dbContext,
            IEmailService emailService,
            ILogger<AccountController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _dbContext = dbContext;
            _emailService = emailService;
            _logger = logger;
        }

        private void AddErrorsToModelState(IEnumerable<IdentityError> identityErrors)
        {
            foreach (var identityError in identityErrors)
            {
                ModelState.TryAddModelError(identityError.Code, identityError.Description);
            }
        }

        /// <summary>
        /// Entry point into the signup workflow
        /// </summary>
        [HttpGet]
        public IActionResult CreateUser(string email, Guid? emailValidationToken, string base64ReturnUrl)
        {

            var createUserViewModel = new CreateUserViewModel
            {
                Email = email,
                Username = email,
                EmailValidationToken = emailValidationToken == new Guid() ? null : emailValidationToken,
                Password = "",
                PasswordRepeat = "",
                Base64ReturnUrl = base64ReturnUrl
            };

            return View(createUserViewModel);
        }

        /// <summary>
        /// Entry point into the signup workflow
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateUser(CreateUserInputModel model)
        {
            var userSignupRequest = await _dbContext.UserSignupRequests.SingleOrDefaultAsync(x => x.EmailValidationToken == model.EmailValidationToken && x.Email == model.Email && x.IsEmailValidationTokenUsed == false);

            if(userSignupRequest == null)
            {
                ModelState.TryAddModelError("", "Did not find any user signup request for this email");
            }
            
            if (!string.Equals(model.Password, model.PasswordRepeat))
            {
                ModelState.TryAddModelError("", "Passwords was not the same.");

                return View(new CreateUserViewModel
                {
                    Base64ReturnUrl = model.Base64ReturnUrl,
                    Email =  model.Email,
                    EmailValidationToken = model.EmailValidationToken,
                    Username =  model.Username
                });
            }

            var user = new ApplicationUser
            {
                Email = model.Email,
                UserName = model.Username,
                EmailConfirmed = true,
            };

            var createUserResult = await _userManager.CreateAsync(user, model.Password);

            if (!createUserResult.Succeeded)
            {
                AddErrorsToModelState(createUserResult.Errors);

                return View(new CreateUserViewModel
                {
                    Base64ReturnUrl = model.Base64ReturnUrl,
                    Email = model.Email,
                    EmailValidationToken = model.EmailValidationToken,
                    Username = model.Username
                });
            }
            var rememberLogin = true; // TODO: Ask user if they actually wants to be remembered

            // TODO Add Member role here, so we know it is a signup member and perhaps also other claims

            var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, rememberLogin, lockoutOnFailure: true);
            if (createUserResult.Succeeded)
            {
                await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName)); // TODO Add clientid context and add return url, so user is returned to the app they tried to access!

                userSignupRequest.IsEmailValidationTokenUsed = true;
                await _dbContext.SaveChangesAsync();

                return Redirect(Base64Decode(model.Base64ReturnUrl)); // Perhaps use client context to check if native how to resolve redirect!
            }
            else
            {
                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials")); // TODO Add clientid context and add return url, so user is returned to the app they tried to access!
                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);

                return View(new CreateUserViewModel
                {
                    Base64ReturnUrl = model.Base64ReturnUrl,
                    Email = model.Email,
                    EmailValidationToken = model.EmailValidationToken,
                    Username = model.Username
                });
            }
        }

        /// <summary>
        /// Entry point into the signup workflow
        /// </summary>
        [HttpGet]
        public IActionResult Delete()
        {
            var viewModel = new DeleteUserViewModel
            {
                IsLocalUser = true
            };

            if (User.IsAuthenticated())
            {
                if (!IsLocalUser())
                {
                    viewModel.IsLocalUser = false;
                }
                else
                {
                    viewModel.Username = GetUsername();
                }
            }

            return View(viewModel);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(DeleteUserInputModel model)
        {
            
            
            if (IsLocalUser()) // Only require user to type signin, if local user.
            {
                var signinResult = await _signInManager.PasswordSignInAsync(model.Username, model.Password, false, true);
                if (!signinResult.Succeeded)
                {
                    ModelState.TryAddModelError("", "Failed to delete user, invalid credentials");

                    return View(new DeleteUserViewModel
                    {
                        Username = model.Username
                    });
                }
            }

            var userToDelete = await _userManager.FindByNameAsync(model.Username);
            var deleteResult = await _userManager.DeleteAsync(userToDelete);

            if (!deleteResult.Succeeded)
            {
                AddErrorsToModelState(deleteResult.Errors);

                return View(new DeleteUserViewModel
                {
                    Username = model.Username
                });
            }

            return RedirectToAction(nameof(Goodbye));
        }

        /// <summary>
        /// Entry point into the signup workflow
        /// </summary>
        [HttpGet]
        public IActionResult Goodbye()
        {

            return View();
        }

        private bool IsLocalUser()
        {
            if (!User.IsAuthenticated())
                return true;

            var loginType = User.Claims.SingleOrDefault(x => string.Equals(x.Type, "amr", StringComparison.InvariantCultureIgnoreCase));

            return loginType != null && !string.IsNullOrEmpty(loginType.Value) && string.Equals(loginType.Value, "pwd",
                StringComparison.InvariantCultureIgnoreCase);
        }

        private string GetUsername()
        {
            return User.Claims.SingleOrDefault(x => x.Type == "preferred_username")?.Value;
        }

        /// <summary>
        /// Entry point into the signup workflow
        /// </summary>
        [HttpGet]
        public IActionResult ChangePassword()
        {
            return View();
        }


        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordInputModel model)
        {
            if (!User.IsAuthenticated())
            {
                ModelState.AddModelError("", "Your not logged in, or your access has just expired. Please login again");

                return View(new ChangePasswordInputModel());
            }

            if (!IsLocalUser())
            {
                ModelState.AddModelError("", "Only local users can change password.");

                return View(new ChangePasswordInputModel());
            }

            var username = GetUsername();

            var user = await _userManager.FindByNameAsync(username);

            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword,model.NewPassword);

            if (!result.Succeeded)
            {
                AddErrorsToModelState(result.Errors);

                return View(new ChangePasswordInputModel());
            }

            return RedirectToAction(nameof(ChangePasswordSuccess));
        }

        /// <summary>
        /// Entry point into the signup workflow
        /// </summary>
        [HttpGet]
        public IActionResult ChangePasswordSuccess()
        {

            return View();
        }

        /// <summary>
        /// Entry point into the signup workflow
        /// </summary>
        [HttpGet]
        public IActionResult Signup(string base64ReturnUrl)
        {
            var signupViewModel = new SignupViewModel
            {
                Base64ReturnUrl = base64ReturnUrl
            };

            return View(signupViewModel);
        }

        
        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Signup(SignupInputModel model)
        {
            var signupViewModel = new SignupViewModel
            {
                Base64ReturnUrl = model.Base64ReturnUrl
            };

            if (!IsValidEmail(model.Email))
            {
                ModelState.AddModelError(string.Empty, "Please ohhh please enter a valid email. We wont spam it :) ");
                return View(signupViewModel);
            }

            var existingUsers = await _dbContext.Users.Where(x => x.Email == model.Email).ToListAsync();

            // There can be several users with same email, because user can signup and login using google
            if (existingUsers.Any())
            {
                ModelState.AddModelError(string.Empty, "User already exists with that email. Please login or recover password");
                return View(signupViewModel);
            }

            var userSignupRequest = await _dbContext.UserSignupRequests.SingleOrDefaultAsync(x => x.Email == model.Email);

            // Dont create new if we already have, but still send new email.
            if (userSignupRequest == null)
            {
                userSignupRequest = new UserSignupRequest
                {
                    Email = model.Email,
                    EmailValidationToken = Guid.NewGuid(),
                    IsEmailValidationTokenUsed = false,
                    ExpireOnUtc = DateTimeOffset.UtcNow.AddDays(1)
                    //Base64ReturnUrl = model.Base64ReturnUrl <-- TODO: Save url in database, so when use clicks link in mail, he get's redirected to page he was visiting
                };

                _dbContext.UserSignupRequests.Add(userSignupRequest);

                await _dbContext.SaveChangesAsync();
            }

            var callback = Url.Action(nameof(CreateUser), "Account", new { email = model.Email, emailValidationToken = userSignupRequest.EmailValidationToken.ToString(), base64ReturnUrl = model.Base64ReturnUrl }, Request.Scheme);

            _logger.LogDebug($"EmailValidationToken is:  \"{userSignupRequest.EmailValidationToken}\"");

            var (plainTextContent, htmlContent) = EmailTemplate.Signup(userSignupRequest.EmailValidationToken.ToString(), callback);
            
            await _emailService.SendEmailAsync(model.Email, "Signup", plainTextContent, htmlContent);

            return Redirect($"~/account/createuser?email={model.Email}&emailValidationToken={new Guid()}&base64ReturnUrl={model.Base64ReturnUrl}");
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordInputModel model)
        {
            // Look at token providers https://code-maze.com/password-reset-aspnet-core-identity/

            if (!ModelState.IsValid)
                return View(new ForgotPasswordViewModel
                {
                    Base64ReturnUrl = model.Base64ReturnUrl,
                    Email = model.Email
                });

            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null)
            {
                return RedirectToAction(nameof(ForgotPasswordConfirmation));
            }
                
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var callback = Url.Action(nameof(ResetPassword), "Account", new { token, email = user.Email }, Request.Scheme);

            var (plainTextContent, htmlContent) = EmailTemplate.ResetPassword(token, callback);

            await _emailService.SendEmailAsync(model.Email,"Reset password", plainTextContent, htmlContent);

            return RedirectToAction(nameof(ForgotPasswordConfirmation));
        }

        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            var model = new ResetPasswordModela { Token = token, Email = email };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordModela resetPasswordModel)
        {
            if (!string.Equals(resetPasswordModel.Password, resetPasswordModel.ConfirmPassword, StringComparison.InvariantCulture))
            {
                ModelState.AddModelError(string.Empty, "Passwords does not match");
            }

            if (!ModelState.IsValid)
                return View(resetPasswordModel);
            var user = await _userManager.FindByEmailAsync(resetPasswordModel.Email);
            if (user == null)
                RedirectToAction(nameof(ResetPasswordConfirmation));
            var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPasswordModel.Token, resetPasswordModel.Password);
            if (!resetPassResult.Succeeded)
            {
                AddErrorsToModelState(resetPassResult.Errors);

                return View();
            }

            return RedirectToAction(nameof(ResetPasswordConfirmation));
        }

        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        public static string Base64Encode(string plainText) // Cleanup
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        public static string Base64Decode(string base64EncodedData) // Cleanup
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

        bool IsValidEmail(string email) // Move to helper or Exstension method?
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl);

            if (returnUrl.Contains("admincallback"))
            {
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", 
                    new { scheme = "OpenIdConnect", provider = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            // check if we are in the context of an authorization request
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            if (string.Equals(button, "signup", StringComparison.InvariantCultureIgnoreCase))
            {
                return Redirect($"~/account/signup?base64ReturnUrl={Base64Encode(model.ReturnUrl)}");
            }

            if (string.Equals(button, "forgotpassword", StringComparison.InvariantCultureIgnoreCase))
            {
                return Redirect($"~/account/forgotpassword?base64ReturnUrl={Base64Encode(model.ReturnUrl)}");
            }

            // the user clicked the "cancel" button
            if (string.Equals(button, "cancel", StringComparison.InvariantCultureIgnoreCase))
            {
                if (context != null)
                {
                    // if the user cancels, send a result back into IdentityServer as if they 
                    // denied the consent (even if this client does not require consent).
                    // this will send back an access denied OIDC error response to the client.
                    await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    if (context.IsNativeClient())
                    {
                        // The client is native, so this change in how to
                        // return the response is for better UX for the end user.
                        return this.LoadingPage("Redirect", model.ReturnUrl);
                    }

                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // since we don't have a valid context, then we just go back to the home page
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    var user = await _userManager.FindByNameAsync(model.Username);
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));

                    if (context != null)
                    {
                        if (context.IsNativeClient())
                        {
                            // The client is native, so this change in how to
                            // return the response is for better UX for the end user.
                            return this.LoadingPage("Redirect", model.ReturnUrl);
                        }

                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                        return Redirect(model.ReturnUrl);
                    }

                    // request for a local page
                    if (Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }
                    else if (string.IsNullOrEmpty(model.ReturnUrl))
                    {
                        return Redirect("~/");
                    }
                    else
                    {
                        // user might have clicked on a malicious link - should be logged
                        throw new Exception("invalid return URL");
                    }
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials", clientId:context?.Client.ClientId));
                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
            }

            // something went wrong, show form with error
            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }

        
        /// <summary>
        /// Show logout page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await _signInManager.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }


        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.Client.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }
    }
}