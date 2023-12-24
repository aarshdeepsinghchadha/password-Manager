using PasswordManager.Common;

namespace PasswordManager.Interfaces.Admin
{
    public interface IResponseGeneratorService
    {
        Task<ReturnResponse> GenerateResponseAsync(bool status, int statusCode, string message);
        Task<ReturnResponse<T>> GenerateResponseAsync<T>(bool status, int statusCode, string message, T data);
    }
}
