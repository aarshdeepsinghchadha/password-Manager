using PasswordManager.Interfaces;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace PasswordManager.Services
{
    public class EmailSenderService : IEmailSenderService
    {
        private readonly IConfiguration _config;
        public EmailSenderService(IConfiguration config)
        {
            _config = config;

        }
        public async Task SendEmailAsync(string userEmail, string emailSubject, string msg)
        {

            var client = new SendGridClient(_config["Sendgrid:Key"]);
            var message = new SendGridMessage
            {
                From = new EmailAddress("aarshdeep.chadha@indianic.com", _config["SendGrid:User"]),
                Subject = emailSubject,
                PlainTextContent = msg,
                HtmlContent = msg
            };
            message.AddTo(new EmailAddress(userEmail));
            message.SetClickTracking(false, false);

            var response = await client.SendEmailAsync(message);
        }

        public async Task SendEmailAsyncWithOTP(string userEmail, string emailSubject, string msg)
        {
            var client = new SendGridClient(_config["Sendgrid:Key"]);

            var message = new SendGridMessage
            {
                From = new EmailAddress("aarshdeep.chadha@indianic.com", _config["SendGrid:User"]),
                Subject = emailSubject,
                PlainTextContent = msg,
                HtmlContent = msg
            };
            message.AddTo(new EmailAddress(userEmail));
            message.SetClickTracking(false, false);
            var response = await client.SendEmailAsync(message);
        }

    }
}
