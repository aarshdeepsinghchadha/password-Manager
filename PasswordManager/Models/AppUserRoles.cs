using Microsoft.AspNetCore.Identity;

namespace PasswordManager.Models
{
    public class AppUserRoles : IdentityUserRole<string>
    {
        public virtual AppUser User { get; set; }
        public virtual Role Role { get; set; }

    }
}
