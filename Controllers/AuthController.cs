using ForumProjectBackend.DbContexts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ForumProjectBackend.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        public class JwtSettings
        {
            public string Key { get; set; } = string.Empty;
            public string Issuer { get; set; } = string.Empty;
            public string Audience { get; set; } = string.Empty;
            public double LifetimeMinutes { get; set; } = 0.0;
        }

        public class AuthRegisterDto
        {
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

            [DataType(DataType.Password)]
            [MaxLength(128)]
            [RegularExpression("^.*(?=.{8,})(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!\"`'#%&,:;<>=@{}~\\$\\(\\)\\*\\+\\/\\\\\\?\\[\\]\\^\\|]).*$")]
            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string Password { get; set; } = string.Empty;

            [DataType(DataType.Password)]
            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            [Compare(nameof(Password))]
            [NotMapped]
            public string ConfirmPassword { get; set; } = string.Empty;
        }

        public class AuthLoginDto
        {
            [DataType(DataType.EmailAddress)]
            [MaxLength(128)]
            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string Email { get; set; } = string.Empty;

            [DataType(DataType.Password)]
            [MaxLength(128)]
            [Required(AllowEmptyStrings = false)]
            [DisplayFormat(ConvertEmptyStringToNull = false)]
            public string Password { get; set; } = string.Empty;
        }

        private readonly JwtSettings _jwtSettings;
        private readonly ForumProjectDbContext _dbContext;

        private static string GenerateToken(AuthLoginDto authDto,
            string jwtKey, string jwtIssuer, string jwtAudience, double jwtLifetimeMinutes)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512Signature);

            var claims = new Claim[]
            {
                new Claim(ClaimTypes.Email, authDto.Email.ToString())
            };

            var token = new JwtSecurityToken(
                issuer: jwtIssuer,
                audience: jwtAudience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(jwtLifetimeMinutes),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public AuthController(IOptions<JwtSettings> jwtSettings, ForumProjectDbContext dbContext)
        {
            _jwtSettings = jwtSettings.Value;
            _dbContext = dbContext;
        }

        [HttpPost]
        [Route("register")]
        [AllowAnonymous]
        public IActionResult Register(AuthRegisterDto authDto)
        {
            if (_dbContext.Users == null)
            {
                throw new ArgumentNullException(nameof(ForumProjectDbContext.Users));
            }

            ForumProjectDbContext.User? existingUser;
            try
            {
                existingUser = _dbContext.Users.Find(authDto.Email);
            }
            catch (Exception)
            {
                return Problem(
                    statusCode: 500,
                    title: "Failed to read data from database."
                );
            }

            if (existingUser != null)
            {
                return BadRequest($"User {authDto.Email} already exists.");
            }

            try
            {
                var newUser = new ForumProjectDbContext.User
                {
                    Email = authDto.Email,
                    DateTimeRegistered = DateTime.UtcNow,
                    IsEmailConfirmed = false,
                    PasswordHash = ForumProjectDbContext.User.HashPassword(authDto.Password)
                };

                _dbContext.Users.Add(newUser);
                _dbContext.SaveChanges();
            }
            catch (Exception)
            {
                return Problem(
                    statusCode: 500,
                    title: "Failed to write data to database."
                );
            }

            return Created(
                HttpContext.Request.Scheme + "://" + HttpContext.Request.Host + HttpContext.Request.Path,
                authDto
            );
        }

        [HttpPost]
        [Route("login")]
        [AllowAnonymous]
        public IActionResult Login(AuthLoginDto authDto)
        {
            if (_dbContext.Users == null)
            {
                throw new ArgumentNullException(nameof(ForumProjectDbContext.Users));
            }

            ForumProjectDbContext.User? user;
            try
            {
                user = _dbContext.Users.Find(authDto.Email);
            }
            catch (Exception)
            {
                return Problem(
                    statusCode: 500,
                    title: "Failed to read data from database."
                );
            }

            if (user == null)
            {
                return NotFound($"User {authDto.Email} not found.");
            }

            if (!ForumProjectDbContext.User.VerifyPassword(authDto.Password, user.PasswordHash))
            {
                return Forbid();
            }

            if (!user.IsEmailConfirmed)
            {
                return Unauthorized($"User {authDto.Email} email not confirmed.");
            }

            return Ok(GenerateToken(
                authDto,
                _jwtSettings.Key,
                _jwtSettings.Issuer,
                _jwtSettings.Audience,
                _jwtSettings.LifetimeMinutes
            ));
        }
    }
}