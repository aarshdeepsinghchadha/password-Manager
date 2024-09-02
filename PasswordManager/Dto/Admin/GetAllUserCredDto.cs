using PasswordManager.Dto.Credentials;

namespace PasswordManager.Dto.Admin
{
    public class GetAllUserCredDto
    {
        public string UserId { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Role { get; set; }

        public List<GetCredDetailsDto>  CredDetails { get; set; }


    }
}
