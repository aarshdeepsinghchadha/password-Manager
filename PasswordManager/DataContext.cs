using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PasswordManager.Models;

namespace PasswordManager
{
    public class DataContext : IdentityDbContext<AppUser>
    {
        public DbSet<Credential> Credentials { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DataContext(DbContextOptions options) : base(options)
        {
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Credential>().HasKey(x => x.Id);
            // Configure the relationship between AppUser and Credential
            modelBuilder.Entity<Credential>()
                .HasOne(c => c.CreatedByUser)
                .WithMany(u => u.Credentials)
                .HasForeignKey(c => c.UserId)
                .IsRequired();

            modelBuilder.Entity<Credential>()
                .HasOne(c => c.UpdatedByUser)
                .WithMany()
                .HasForeignKey(c => c.LastUpdatedByUserId);

            modelBuilder.Entity<Credential>()
                .HasOne(c => c.DeletedByUser)
                .WithMany()
                .HasForeignKey(c => c.DeletedByUserId);

            modelBuilder.Entity<RefreshToken>()
               .HasOne(x => x.AppUser)
               .WithMany(x => x.RefreshTokens)
               .HasForeignKey(x => x.AppUserId)
               .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
