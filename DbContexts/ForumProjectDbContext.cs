using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace ForumProjectBackend.DbContexts
{
    public class ForumProjectDbContext : DbContext
    {
        public class User
        {
            [Key]
            [DataType(DataType.EmailAddress)]
            [MaxLength(128)]
            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string Email { get; set; } = string.Empty;

            /*
                - At least one lower case letter.
                - At least one upper case letter.
                - At least one special character: !"`'#%&,:;<>=@{}~$()*+/\?[]^|
                - At least one number.
                - At least 8 characters length.
            */

            [MaxLength(128)]
            [RegularExpression("^.*(?=.{8,})(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!\"`'#%&,:;<>=@{}~\\$\\(\\)\\*\\+\\/\\\\\\?\\[\\]\\^\\|]).*$")]
            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string Password { get; set; } = string.Empty;
        }

        public ForumProjectDbContext(DbContextOptions<ForumProjectDbContext> options) :
            base(options)
        {
        }

        public DbSet<User>? Users { get; set; }
    }
}