using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations.Schema;

namespace PasswordManager.Models
{
    public class Role : IdentityRole<string>
    {
        public Role()
        {
            this.Id = Guid.NewGuid().ToString();
        }

        public Role(string name)
            : this()
        {
            this.Name = name;
        }
        public string Description { get; set; }
        [ForeignKey("AddedByUser")]
        public string AddedbyUserId { get; set; }
        public virtual AppUser AddedByUser { get; set; }
        public bool Status { get; set; }
        public bool IsDeleted { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }

        public bool isDefault { get; set; }
        [ForeignKey("ModifiedByUser")]
        public string ModifiedByUserId { get; set; }
        public virtual AppUser ModifiedByUser { get; set; }

        #region Relationships
        public virtual ICollection<AppUserRoles> AppUserRoles { get; set; }
        #endregion
    }
}
