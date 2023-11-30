namespace PasswordManager.Interfaces
{
    public interface IEmailSenderService
    {
        Task SendEmailAsync(string userEmail, string emailSubject, string msg);
        Task SendEmailAsyncWithOTP(string userEmail, string emailSubject, string msg);
    }
}
