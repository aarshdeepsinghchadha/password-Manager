using PasswordManager.Common;
using PasswordManager.Interfaces;

namespace PasswordManager.Services
{
    public class ResponseGeneratorService : IResponseGeneratorService
    {
        public async Task<ReturnResponse> GenerateResponseAsync(bool status, int statusCode, string message)
        {
            return new ReturnResponse
            {
                Status = status,
                StatusCode = statusCode,
                Message = message
            };
        }

        public async Task<ReturnResponse<T>> GenerateResponseAsync<T>(bool status, int statusCode, string message, T data)
        {
            return new ReturnResponse<T>
            {
                Status = status,
                StatusCode = statusCode,
                Message = message,
                Data = data
            };
        }
    }
}
