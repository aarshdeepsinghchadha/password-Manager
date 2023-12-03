using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace PasswordManager.Models
{
    public class RefreshToken
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string Id { get; set; }
        public string AppUserId { get; set; }
        public AppUser AppUser { get; set; }
        public string Token { get; set; }
        public DateTime Expires { get; set; } = DateTime.UtcNow.AddMinutes(30);
        public bool IsExpired => DateTime.UtcNow >= this.Expires;
        public DateTime? Revoked { get; set; }
        public bool IsActive => Revoked == null && !IsExpired;
    }
}
