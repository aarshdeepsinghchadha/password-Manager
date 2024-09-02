using Microsoft.AspNetCore.Identity;

namespace PasswordManager.Models
{
    public class AppUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Role { get; set; }

        // Navigation property for one-to-many relationship
        public ICollection<Credential> Credentials { get; set; }
        public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
        public virtual ICollection<AppUserRoles> AppUserRoles { get; set; }
        public ICollection<Role> Roles { get; set; }
        public ICollection<Role> AddedByRoles { get; set; }
    }
}
