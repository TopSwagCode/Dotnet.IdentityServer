using SendGrid;
using SendGrid.Helpers.Mail;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace IdentityServerAspNetIdentity.Services
{
    public class EmailTemplate
    {

        public static (string plainTextContent, string htmlContent) ResetPassword(string token, string callback) =>
            (
                $"Here is your reset password token: {token}",
                $"<strong>Here is your validation token link: <a href='{callback}'>Helloooo</a><br/> Here is your token if you can't press the link: {token}</strong>" // TODO  Better text maybe some css
            );

        public static (string plainTextContent, string htmlContent) Signup(string token, string callback) =>
        (
            $"Here is your validation token: {token}",
            $"<strong>Here is your validation token link: <a href='{callback}'>Helloooo</a><br/> Here is your token if you can't press the link: {token}</strong>" // TODO  Better text maybe some css
        );
    }

    public interface IEmailService
    {
        Task SendEmailAsync(string email, string subject, string plainTextContent, string htmlContent);
    }

    public class EmailService : IEmailService
    {
        private readonly ISendGridClient _sendGridClient;
        private readonly ILogger<EmailService> _logger;

        public EmailService(ISendGridClient sendGridClient, ILogger<EmailService> logger)
        {
            _sendGridClient = sendGridClient;
            _logger = logger;
        }

        public async Task SendEmailAsync(string email, string subject, string plainTextContent, string htmlContent)
        {
            var from = new EmailAddress("joshua@help-motivate.me", "Help-Motivate.Me");
            var to = new EmailAddress(email, email);

            var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
            var response = await _sendGridClient.SendEmailAsync(msg);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError($"Failed to send email with StatusCode: {response.StatusCode}");
            }
        }
    }
}
