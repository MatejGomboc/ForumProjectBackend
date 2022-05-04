using ForumProjectBackend.DbContexts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ForumProjectBackend.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly ForumProjectDbContext _dbContext;

        private static string GenerateToken(ForumProjectDbContext.User user,
            string jwtKey, string jwtIssuer, string jwtAudience)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512Signature);

            var claims = new Claim[]
            {
                new Claim(ClaimTypes.Email, user.Email.ToString())
            };

            var token = new JwtSecurityToken(
                issuer: jwtIssuer,
                audience: jwtAudience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public AuthController(IConfiguration config, ForumProjectDbContext dbContext)
        {
            _config = config;
            _dbContext = dbContext;
        }

        [HttpPost]
        [Route("register")]
        [AllowAnonymous]
        public IActionResult Register(ForumProjectDbContext.User userDto)
        {
            if (_dbContext.Users == null)
            {
                throw new ArgumentNullException(nameof(ForumProjectDbContext.Users));
            }

            ForumProjectDbContext.User? existingUser;
            try
            {
                existingUser = _dbContext.Users.Find(userDto.Email);
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
                return BadRequest($"User {userDto.Email} already exists.");
            }

            try
            {
                _dbContext.Users.Add(userDto);
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
                userDto
            );
        }

        [HttpPost]
        [Route("login")]
        [AllowAnonymous]
        public IActionResult Login(ForumProjectDbContext.User userDto)
        {
            if (_dbContext.Users == null)
            {
                throw new ArgumentNullException(nameof(ForumProjectDbContext.Users));
            }

            ForumProjectDbContext.User? user;
            try
            {
                user = _dbContext.Users.Find(userDto.Email);
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
                return NotFound($"User {userDto.Email} not found.");
            }

            if (user.Password != userDto.Password)
            {
                return Forbid();
            }

            return Ok(GenerateToken(
                user,
                _config.GetSection("Jwt:Key").Value,
                _config.GetSection("Jwt:Issuer").Value,
                _config.GetSection("Jwt:Audience").Value
            ));
        }
    }
}