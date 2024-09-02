using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PasswordManager.Models;

namespace PasswordManager
{
    //public class DataContext : IdentityDbContext<AppUser>
    public class DataContext : IdentityDbContext<AppUser, Role, string, IdentityUserClaim<string>, AppUserRoles, IdentityUserLogin<string>, IdentityRoleClaim<string>, IdentityUserToken<string>>
    {
        public DbSet<Credential> Credentials { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<IdentityRole> IdentityRoles { get; set; }
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

            modelBuilder.Entity<RefreshToken>()
               .HasOne(x => x.AppUser)
               .WithMany(x => x.RefreshTokens)
               .HasForeignKey(x => x.AppUserId)
               .OnDelete(DeleteBehavior.Cascade);


            modelBuilder.Entity<AppUser>()
              .HasMany(x => x.Roles)
              .WithOne(x => x.ModifiedByUser)
              .HasForeignKey(x => x.ModifiedByUserId);

            modelBuilder.Entity<AppUser>()
               .HasMany(x => x.AddedByRoles)
               .WithOne(x => x.AddedByUser)
               .HasForeignKey(x => x.AddedbyUserId);

            modelBuilder.Entity<Role>()
                .HasMany(m => m.AppUserRoles)
                .WithOne(m => m.Role)
                .HasForeignKey(m => m.RoleId)
                .OnDelete(DeleteBehavior.Cascade)
                .IsRequired();

            modelBuilder.Entity<AppUser>()
                .HasMany(m => m.AppUserRoles)
                .WithOne(m => m.User)
                .HasForeignKey(m => m.UserId)
                .OnDelete(DeleteBehavior.Cascade)
                .IsRequired();
        }
    }
}
