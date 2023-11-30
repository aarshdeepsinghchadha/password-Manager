using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PasswordManager.Models;

namespace PasswordManager
{
    public class DataContext : IdentityDbContext<AppUser>
    {
        public DbSet<Credential> Credentials { get; set; }
        public DataContext(DbContextOptions options) : base(options)
        {
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure the relationship between AppUser and Credential
            modelBuilder.Entity<Credential>()
                .HasOne(c => c.AppUser)
                .WithMany(u => u.Credentials)
                .HasForeignKey(c => c.UserId)
                .IsRequired();
        }
    }
}
