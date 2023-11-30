namespace PasswordManager.Dto
{
    public class RefreshTokenDto
    {
        public string OldToken {  get; set; }
        public string Email { get; set; }
    }
}
