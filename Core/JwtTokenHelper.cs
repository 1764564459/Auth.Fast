using IdentityModel;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Fast.Core
{
    public class JwtTokenHelper
    {
        IConfiguration _config;
        public JwtTokenHelper(IConfiguration config)
        {
            _config = config;
        }

        public string GrantToken()
        {
            var token_handler = new JwtSecurityTokenHandler();
            var _secret = _config.GetSection("").GetValue<string>("");
            var _key = Encoding.UTF8.GetBytes(_secret);
            var token_desc = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new[]
                {
                 new Claim(JwtClaimTypes.Audience,"api"),
                 new Claim(JwtClaimTypes.Issuer,"http://localhost:5000"),
                 new Claim(JwtClaimTypes.Id,""),
                 new Claim(JwtClaimTypes.Name,""),
                 new Claim(JwtClaimTypes.Email,""),
                 new Claim(JwtClaimTypes.PhoneNumber,"")
                }),
                Expires=DateTime.UtcNow.AddSeconds(20),

            };

            var _token = token_handler.CreateToken(token_desc);
            return token_handler.WriteToken(_token);
        }
    }
}
