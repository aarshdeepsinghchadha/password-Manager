﻿using PasswordManager.Common;

namespace PasswordManager.Interfaces.Admin
{
    public interface IEmailSenderService
    {
        Task<ReturnResponse> SendEmailUsingSendGridAsync(string userEmail, string emailSubject, string msg);
        Task<ReturnResponse> SendEmailUsingMailGunAsync(string userEmail, string emailSubject, string msg);
    }
}
