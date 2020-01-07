using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repos;
        private readonly IConfiguration _config;
        public AuthController(IAuthRepository repos, IConfiguration config)
        {
            _config = config;
            _repos = repos;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
        {
            userForRegisterDto.Username = userForRegisterDto.Username.ToLower(); // make sure consistent sata in the database.
            if (await _repos.UserExists(userForRegisterDto.Username))
                return BadRequest("Username already exists");

            var userToCreate = new User
            {
                Username = userForRegisterDto.Username
            };

            var createdUser = await _repos.Register(userToCreate, userForRegisterDto.Password);
            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
        {
            var userFromRepo = await _repos.Login(userForLoginDto.Username.ToLower(), userForLoginDto.Password);
            // check and make sure that we have a user and their username and password matches what stored in the database for that particular user.

            if (userFromRepo == null)
                return Unauthorized();

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name, userFromRepo.Username)
            };
            // the token contains two claims: one is the user's ID and other is the user's username

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));
            // we want to store this key inside the AppSettings because we're gonna use it in a couple of different places.
            // we'll need to store it much in the same way we're storing our connection string information in AppSettings.
            // We need to bring in (inject) the configuration into the controller.
            
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            // in order to make sure that the tokens are valid token. when it comes back. the server needs to sign the token.
            // so we create a security key and then we used this key as part of the signing credentials, 
            // and encryptd this key with a hashing algorithm. 

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = creds
            };
            // start to actually create the token. we created the token descriptor and we passed the claims as the subjects.
            // we gave an expire date. and passed in the signing credentials as well which we created above.


            var tokenHandler = new JwtSecurityTokenHandler();
            
            var token = tokenHandler.CreateToken(tokenDescriptor);
            // created a new JWT security token handler which is linked to allow us to create the token based on the token descriptor.
            // and we stored the token variable 

            return Ok(new {
                token = tokenHandler.WriteToken(token)
            });
            // we used the token variable to write the token into a response that we send back to the clients.
        }
    }
}