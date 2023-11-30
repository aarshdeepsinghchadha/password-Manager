using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PasswordManager.Models
{
    public class Credential
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public Guid Id { get; set; }
        /// <summary>
        /// Unique Identifier for the user creating the credentials
        /// </summary>
        public string UserId { get; set; }
        /// <summary>
        /// The Name of the Website 
        /// </summary>
        public string WebsiteName { get; set; }
        /// <summary>
        /// Username or Email
        /// </summary>
        public string Username { get; set; }
        /// <summary>
        /// Password
        /// </summary>
        public string Password { get; set; }

        // Navigation property for the related user
        public AppUser AppUser { get; set; }
    }
}
