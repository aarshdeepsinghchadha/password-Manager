using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PasswordManager;
using PasswordManager.Interfaces;
using PasswordManager.Models;
using PasswordManager.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure the connection string
var connectionString = builder.Configuration.GetConnectionString("PasswordManager");

// Add services to the container.
builder.Services.AddDbContext<DataContext>(options =>
    options.UseNpgsql(connectionString));

// Add Identity
builder.Services.AddIdentity<AppUser, IdentityRole>()
    .AddEntityFrameworkStores<DataContext>()
    .AddDefaultTokenProviders();

// Explicitly add UserManager and SignInManager
builder.Services.AddScoped<UserManager<AppUser>>();
builder.Services.AddScoped<SignInManager<AppUser>>();

builder.Services.AddScoped<IResponseGeneratorService, ResponseGeneratorService>();
builder.Services.AddScoped<IAdminService, AdminService>();



var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
