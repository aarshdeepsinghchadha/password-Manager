using PasswordManager.Common;
using PasswordManager.Interfaces;
using RestSharp.Authenticators;
using RestSharp;
using SendGrid;
using SendGrid.Helpers.Mail;
using static System.Net.WebRequestMethods;


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

       

        public async Task<ReturnResponse> SendEmailUsingSendGridAsync(string userEmail, string emailSubject, string msg)
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
                    return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status400BadRequest, $"An error occurred SendEmailUsingSendGridAsync {response.StatusCode}");
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
                    false, StatusCodes.Status500InternalServerError, $"An error occurred SendEmailUsingSendGridAsync {ex.Message}");
            }
        }
        public async Task<ReturnResponse> SendEmailUsingMailGunAsync(string userEmail, string emailSubject, string msg)
        {
            var apiKey = _config["MailGun:Key"];
            var domainName = _config["MailGun:DomainName"];
            var baseurl = "https://api.mailgun.net/v3";
            var request = new RestRequest();
            request.Authenticator = new HttpBasicAuthenticator("api", apiKey);
            request.AddParameter("domain", domainName, ParameterType.UrlSegment);
            request.Resource = $"{baseurl}/{domainName}/messages";
            request.AddParameter("from", "aarshdeep.chadha@indianic.com");
            request.AddParameter("to", userEmail);
            request.AddParameter("subject", emailSubject);
            request.AddParameter("html", msg);
            request.Method = Method.Post;

            RestClient restClient = new RestClient();
            var result = restClient.Execute(request);
            if (!result.IsSuccessful)
            {
                return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status200OK, $"Email was not  sent successfully : {result.ErrorMessage}");
            }
            else
            {
                return await _responseGeneratorService.GenerateResponseAsync(true, StatusCodes.Status200OK, $"Email was sent successfully : {result.StatusCode}");
            }
        }

       



    }
}
