using PasswordManager.Common;

namespace PasswordManager.Interfaces
{
    public interface IEmailSenderService
    {
        Task<ReturnResponse> SendEmailAsync(string userEmail, string emailSubject, string msg);
    }
}
