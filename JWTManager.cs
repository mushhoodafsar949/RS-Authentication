using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Security.Cryptography;
using RS_Authentication_Server.App_Start;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;

namespace RS_Authentication_Server
{
    public static class JWTManager
    {
        public static string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        public static string GenerateAccessToken(string username, string role, long userId)
        {
            DateTime issuedAt = DateTime.UtcNow;
            DateTime expires = DateTime.UtcNow.AddMinutes(GlobalVariables.JWTTokenDuration); var tokenHandler = new JwtSecurityTokenHandler(); ClaimsIdentity claimsIdentity = new ClaimsIdentity(new[] {
 new Claim(ClaimTypes.Name,username),
 new Claim(ClaimTypes.Role,role),
 new Claim("UserId",userId.ToString())
 });
            var now = DateTime.UtcNow;
            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(GlobalVariables.JWTSecret));
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
            var token = tokenHandler.CreateJwtSecurityToken(
            issuer: ConfigurationManager.AppSettings["audience"],
            audience: ConfigurationManager.AppSettings["issuer"],
            subject: claimsIdentity,
            notBefore: issuedAt,
            expires: expires,
            signingCredentials: signingCredentials
            );
            var tokenString = tokenHandler.WriteToken(token);
            return tokenString;
        }
    }
}