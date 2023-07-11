using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace RS_Authentication_Server.Models
{
    public class TokenRequestModel
    {
        public string Grant_Type { get; set; }
        public string ClientId { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Refresh_Token { get; set; }
    }
}