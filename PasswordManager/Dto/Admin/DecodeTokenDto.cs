using PasswordManager.Models;

namespace PasswordManager.Dto
{
    public class DecodeTokenDto
    {
        public bool Status {  get; set; }
        public AppUser UserDetails { get; set; }
    }
}
