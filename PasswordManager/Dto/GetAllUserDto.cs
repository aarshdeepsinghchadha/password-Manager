﻿namespace PasswordManager.Dto
{
    public class GetAllUserDto
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Username { get; set; }
        public bool EmailConfirmed { get; set; }
    }
}
