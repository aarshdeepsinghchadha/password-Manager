using Microsoft.AspNetCore.Identity;
using PasswordManager.Dto;
using PasswordManager.Models;

namespace PasswordManager
{
    public class Seed
    {
        public static async Task SeedData(DataContext context, UserManager<AppUser> userManager, RoleManager<Role> roleManager)
        {
            #region AdminUser
            var passwordHasher = new PasswordHasher<AppUser>();
            var users = new List<AppUser>
            {
                new AppUser
                {
                    FirstName = "Aarshdeep",
                    LastName = "Chadha",
                    UserName = "Aarshdeep.Chadha",
                    Email = "ascnyc29@gmail.com",
                    EmailConfirmed = true,
                    PhoneNumber = "4282342140",
                    Role = "Administrator"
                }
            };

            if (!userManager.Users.Any())
            {
                foreach (var user in users)
                {
                    await userManager.CreateAsync(user, "Pa$$w0rd");
                }

                await context.SaveChangesAsync();
            }

            #endregion

            #region Roles

            if (!roleManager.Roles.Any())
            {
                // Make sure the user with AddedbyUserId exists
                var addedByUser = userManager.Users.FirstOrDefault(x => x.UserName == "Aarshdeep.Chadha");

                if (addedByUser != null)
                {
                    await roleManager.CreateAsync(new Role
                    {
                        Name = "Administrator",
                        Description = "Admin of the app",
                        AddedbyUserId = addedByUser.Id,
                        Status = true,
                        IsDeleted = false,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow,
                        isDefault = false,
                        ModifiedByUserId = addedByUser.Id
                    });

                    await roleManager.CreateAsync(new Role
                    {
                        Name = "User",
                        Description = "Default User of the app",
                        AddedbyUserId = addedByUser.Id,
                        Status = true,
                        IsDeleted = false,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow,
                        isDefault = false,
                        ModifiedByUserId = addedByUser.Id
                    });


                    var userrole = new List<AppUserRoles>
                    {
                        new AppUserRoles
                        {
                            RoleId = roleManager.Roles.FirstOrDefault(x => x.Name == "Administrator")?.Id,
                            UserId = addedByUser.Id,
                        }
                    };

                    if (context.UserRoles != null)
                    {
                        await context.UserRoles.AddRangeAsync(userrole);
                        await context.SaveChangesAsync();
                    }
                }
            }

            #endregion


        }
    }
}
