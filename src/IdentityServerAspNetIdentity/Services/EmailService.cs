using SendGrid;
using SendGrid.Helpers.Mail;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerAspNetIdentity.Services
{
    public class EmailService
    {
        public async Task sendemail()
        {
            var apiKey = "######";
            var client = new SendGridClient(apiKey);
            var from = new EmailAddress("joshua@help-motivate.me", "Joshua Ryder");
            var subject = "Sending with Twilio SendGrid is Fun";
            var to = new EmailAddress("josh@topswagcode.com", "Joshua Jesper Krægpøth Ryder");
            var plainTextContent = "and easy to do anywhere, even with C#";
            var htmlContent = "<strong>and easy to do anywhere, even with C#</strong>";
            var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
            var response = await client.SendEmailAsync(msg).ConfigureAwait(false);
        }

        public async Task SendSignupEmail(string email, Guid emailValidationToken, string base64ReturnUrl)
        {
            var apiKey = "#######";
            var client = new SendGridClient(apiKey);
            var from = new EmailAddress("joshua@help-motivate.me", "Signup Help-Motivate.me");
            var subject = "Signup validation for Help-Motivate.me";
            var to = new EmailAddress(email, "Joshua Jesper Krægpøth Ryder");
            
            var plainTextContent = $"Here is your validation token: {emailValidationToken}";
            var htmlContent = $"<strong>Here is your validation token link: <a href='http://localhost:5000/account/createuser?email={email}&emailValidationToken={emailValidationToken.ToString()}&base64ReturnUrl={base64ReturnUrl}'>Helloooo</a><br/> Here is your token if you can't press the link: {emailValidationToken}</strong>";
            
            var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
            var response = await client.SendEmailAsync(msg).ConfigureAwait(false); // Handle this for retry
        }
    }

    
}
