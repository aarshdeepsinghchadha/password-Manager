using Microsoft.Extensions.Primitives;

namespace PasswordManager.Dto
{
    public class RefreshResponseDto
    {
        public string Token { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
    }
}
