// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4;
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
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerHost.Quickstart.UI
{
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
        private readonly EmailService _emailService;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            ApplicationDbContext dbContext,
            EmailService emailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _dbContext = dbContext;
            _emailService = emailService;
        }

        /// <summary>
        /// Entry point into the signup workflow
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> CreateUser(string email, Guid? emailValidationToken, string base64ReturnUrl)
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
                throw new NotImplementedException("Could not find UserSignupRequest for given token / email"); // Handle this!
            }
            
            if (!string.Equals(model.Password, model.PasswordRepeat))
            {
                throw new NotImplementedException("Passwords did not match!"); // Handle this!
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
                throw new NotImplementedException($"Failed to create new user! Errors: [ { string.Join(" - ",createUserResult.Errors.Select(x => $"Code: {x.Code}, Description: {x.Description}").ToList()) } ]"); // Handle this!
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
            }
            

            throw new NotImplementedException("Handle failed login attempt and what to do!");
        }

        /// <summary>
        /// Entry point into the signup workflow
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Signup(string base64ReturnUrl)
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
            // TODO Propper Validate email and show errors
            // TODO Save redirect url for Create User Workflow, so User can be returned to the app they tried to access! This is a must if several apps accesses the same user signup flow! For now hardcoded for javascript client

            if (!IsValidEmail(model.Email))
            {
                throw new Exception("Invalid email. This should be handled!");
            }

            // Check if existing Token for email exists that is not expired before creating new
            // If problem with many requests remove old requests in future, or move to history table

            //var token = await _userManager.GenerateEmailConfirmationTokenAsync(); We could use built in logic
            // But I don't want users that never completes the flow in the database. I have no right to keep emails of none active users!

            UserSignupRequest userSignupRequest = new UserSignupRequest
            {
                Email = model.Email,
                EmailValidationToken = Guid.NewGuid(),
                IsEmailValidationTokenUsed = false,
                ExpireOnUtc = DateTimeOffset.UtcNow.AddDays(1)
                //Base64ReturnUrl = model.Base64ReturnUrl <-- TODO: Save url in database, so when use clicks link in mail, he get's redirected to page he was visiting
            };

            _dbContext.UserSignupRequests.Add(userSignupRequest);

            // Send email with EmailValidationToken

            await _dbContext.SaveChangesAsync();

            await _emailService.SendSignupEmail(model.Email, userSignupRequest.EmailValidationToken, model.Base64ReturnUrl);

            return Redirect($"~/account/createuser?email={model.Email}&emailValidationToken={((new Guid()).ToString())}&base64ReturnUrl={model.Base64ReturnUrl}");
        }

        /// <summary>
        /// Entry point into the signup workflow
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> ForgotPassword(string base64ReturnUrl)
        {
            var forgotPasswordViewModel = new ForgotPasswordViewModel
            {
                Base64ReturnUrl = base64ReturnUrl
            };

            return View(forgotPasswordViewModel);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordInputModel model)
        {
            // Look at token providers https://code-maze.com/password-reset-aspnet-core-identity/

            throw new NotImplementedException("Not implemented");
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

            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { provider = vm.ExternalLoginScheme, returnUrl });
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