using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MySqlConnector;
using DotNetEnv;
// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace WebAPI.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration configuration;
        public AuthController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }
        
        // POST api/values
        [HttpPost]
        public IActionResult Authenticate([FromBody]Credential credential)
        {
            string uname = string.Empty;
            string pw = string.Empty;
            //try
            //{
            //    DotNetEnv.Env.Load();
            //    var password = Environment.GetEnvironmentVariable("PASSWORD");
            //    var server = Environment.GetEnvironmentVariable("SERVER");
            //    var user = Environment.GetEnvironmentVariable("USER");
            //    var database = Environment.GetEnvironmentVariable("DATABASE");
            //    String connectionString = $"server={server};user={user};password={password};database={database}";
            //    using (MySqlConnection connection = new MySqlConnection(connectionString))
            //    {
            //        connection.Open();
            //        string query = "SELECT * FROM Users WHERE username = @username";
            //        using (MySqlCommand command = new MySqlCommand(query, connection))
            //        {
            //            command.Parameters.AddWithValue("@username", credential.UserName);
            //            using (MySqlDataReader reader = command.ExecuteReader())
            //            {
            //                if (reader.HasRows)
            //                {
            //                    while (reader.Read())
            //                    {
            //                        //Console.WriteLine(reader.GetString(1));
            //                        //Console.WriteLine(reader.GetString(2));
            //                        uname = reader.GetString(1);
            //                        pw = reader.GetString(2);
            //                    }
            //                }
            //            }
            //        }
            //    }

            //}
            //catch (Exception ex)
            //{
            //    Console.WriteLine(ex.Message);
            //}
            if (credential.UserName == "admin" && credential.Password == "password"/*BCrypt.Net.BCrypt.Verify(credential.Password, pw)*/)
            {
                //Console.WriteLine("Successfully verified");
                //creating the security context
                var claims = new List<Claim>
            {
                //here are the claims the web api app includes
                new Claim(ClaimTypes.Name, "admin"),
                new Claim(ClaimTypes.Email, "admin@email.com"),
                new Claim("Admin", "true"),
                new Claim("Identity","Owner"),
                new Claim("Identity","Authenticated"),
                new Claim("Owner", "true"),
                new Claim("FreeTrialStartDate", "2023-03-01")
            };
                //Here starts to implement json web token mechanism, which is different from cookie mechanism under login from the sql app
                //expiration for the token
                var expiresAt = DateTime.UtcNow.AddMinutes(10);
                return Ok(new { access_token = CreateToken(claims, expiresAt), expires_at = expiresAt});
            }
            ModelState.AddModelError("Unauthorized", "You are not authorized to access the endpoint.");
            return Unauthorized(ModelState);
        }

        private string CreateToken(IEnumerable<Claim> claims, DateTime expiresAt)
        {
            var secretKey = System.Text.Encoding.ASCII.GetBytes(configuration.GetValue<string>("SecretKey"));
            var jwt = new JwtSecurityToken(
                    claims: claims,
                    notBefore: DateTime.UtcNow,
                    expires: expiresAt,
                    signingCredentials: new SigningCredentials(
                        new SymmetricSecurityKey(secretKey),
                        SecurityAlgorithms.HmacSha256Signature
                    )
               );
            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }
       
    }
    public class Credential
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }
}

