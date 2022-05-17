using Isopoh.Cryptography.Argon2;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace ForumProjectBackend.DbContexts
{
    public class ForumProjectDbContext : DbContext
    {
        public class User
        {
            public static string HashPassword(string password)
            {
                return Argon2.Hash(password);
            }

            public static bool VerifyPassword(string password, string passwordHash)
            {
                return Argon2.Verify(passwordHash, password);
            }

            [Key]
            [DataType(DataType.EmailAddress)]
            [MaxLength(128)]
            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string Email { get; set; } = string.Empty;

            [DataType(DataType.DateTime)]
            [Required]
            public DateTime DateTimeRegistered { get; set; } = DateTime.UnixEpoch;

            [Required]
            public bool IsEmailConfirmed { get; set; } = false;

            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string PasswordHash { get; set; } = string.Empty;
        }

        public ForumProjectDbContext(DbContextOptions<ForumProjectDbContext> options) :
            base(options)
        {
        }

        public DbSet<User>? Users { get; set; }
    }
}