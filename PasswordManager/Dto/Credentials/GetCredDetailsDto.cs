namespace PasswordManager.Dto.Credentials
{
    public class GetCredDetailsDto
    {
        public Guid Id {  get; set; }
        public string WebsiteName { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public string? LastUpdatedByUser { get; set; }
    }
}
