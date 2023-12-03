using PasswordManager.Common;
using PasswordManager.Interfaces;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace PasswordManager.Services
{
    public class EmailSenderService : IEmailSenderService
    {
        private readonly IConfiguration _config;
        private readonly IResponseGeneratorService _responseGeneratorService;
        public EmailSenderService(IConfiguration config, IResponseGeneratorService responseGeneratorService)
        {
            _config = config;
            _responseGeneratorService = responseGeneratorService;
        }
        public async Task<ReturnResponse> SendEmailAsync(string userEmail, string emailSubject, string msg)
        {
            try
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
                if(!response.IsSuccessStatusCode)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status400BadRequest, $"An error occurred SendEmailAsync {response.StatusCode}");
                }
                else
                {
                    return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status200OK, $"Email was sent successfully : {response.StatusCode}");
                }
            }
            catch(Exception ex)
            {
                // Handle other exceptions
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred SendEmailAsync {ex.Message}");
            }
        }
    }
}
