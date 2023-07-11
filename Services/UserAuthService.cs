using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Net;
using System.Net.Mail;
using RS_Authentication_Server.Models;
using System.Security.Cryptography;
using System.Net.Http;
using System.Web.Http;
using System.Configuration;
using System.IO;


using System.Web.UI;
using System.Web.UI.WebControls;
using System.Net.NetworkInformation;

namespace RS_Authentication_Server.Services
{
    public class UserAuthService
    {
       

        //password encryption
        public string HashPassword(string password)
        {
            byte[] salt;
            byte[] buffer2;
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }
            using (Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(password, 0x10, 0x3e8))
            {
                salt = bytes.Salt;
                buffer2 = bytes.GetBytes(0x20);
            }
            byte[] dst = new byte[0x31];
            Buffer.BlockCopy(salt, 0, dst, 1, 0x10);
            Buffer.BlockCopy(buffer2, 0, dst, 0x11, 0x20);
            return Convert.ToBase64String(dst);
        }

        //Password Decrypting
        public bool VerifyHashedPassword(string hashedPassword, string password)
        {
            byte[] buffer4;
            if (hashedPassword == null)
            {
                return false;
            }
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }
            byte[] src = Convert.FromBase64String(hashedPassword);
            if ((src.Length != 0x31) || (src[0] != 0))
            {
                return false;
            }
            byte[] dst = new byte[0x10];
            Buffer.BlockCopy(src, 1, dst, 0, 0x10);
            byte[] buffer3 = new byte[0x20];
            Buffer.BlockCopy(src, 0x11, buffer3, 0, 0x20);
            using (Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(password, dst, 0x3e8))
            {
                buffer4 = bytes.GetBytes(0x20);
            }
            return ByteArraysEqual(buffer3, buffer4);
        }


        private bool ByteArraysEqual(byte[] a, byte[] b)
        {

            if (ReferenceEquals(a, b))
            {
                return true;
            }

            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }

            bool areSame = true;
            for (int i = 0; i < a.Length; i++)
            {
                areSame &= (a[i] == b[i]);
            }
            return areSame;
        }


        public string myauthmailsender(string receiverEmail, string Username)
        {
            try
            {
                var fromAddress = new MailAddress(ConfigurationManager.AppSettings["username"].ToString(), "NOBILITY RCM");
                var toAddress = new MailAddress(receiverEmail);
                string pass = ConfigurationManager.AppSettings["password"].ToString();
                string fromPassword = pass;
                const string subject = "Reporting Server OTP Authentication";
                string newotp = Randomnumbergenerator();
                var checkduplicate=checkforDuplication(newotp);
                string uniqueOTP= checkuniqueness(checkduplicate);

                //Fetching Email Body Text from EmailTemplate File.  
                string FilePath = HttpContext.Current.Server.MapPath("~/Email Templates/Emailtemplate.html"); ;    
                StreamReader str = new StreamReader(FilePath);
                string MailText = str.ReadToEnd();
                str.Close();

                var smtp = new SmtpClient
                {
                    Host = ConfigurationManager.AppSettings["smtp"].ToString(),
                    Port = Convert.ToInt16(ConfigurationManager.AppSettings["portnumber"]),
                    //Port = 25,
                    EnableSsl = Convert.ToBoolean(ConfigurationManager.AppSettings["IsSSL"]),
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    UseDefaultCredentials = false,
                    Credentials = new NetworkCredential(fromAddress.Address, fromPassword)
                };
                MailText = MailText.Replace("123456", uniqueOTP);
                MailText = MailText.Replace("John", Username);

                using (var message = new MailMessage(fromAddress, toAddress)
                {
                    IsBodyHtml = true,
                    Subject = subject,
                    Body = MailText,
                   // Body = body
                })
                {
                    smtp.Send(message);
                }


                return uniqueOTP;


            }

            catch (SmtpFailedRecipientException)
            {
                throw;
            }
        }

        string Randomnumbergenerator()
        {
            Random random = new Random();
            string opt = random.Next(100000, 999999).ToString();
            return opt;
        }



       string checkuniqueness(bool val)
        {
            var uniqueOTP = Randomnumbergenerator();
                val = checkforDuplication(uniqueOTP);
            if(val==true && uniqueOTP != "")
            {
                return uniqueOTP;
            }
            else
            {
               return checkuniqueness(val);
            }
           
        }



        public bool checkforDuplication(string OTP)
        {
            using (NPMDevDBEntities6 db = new NPMDevDBEntities6())
            {
                long ccc = Convert.ToInt64(OTP);
                var OTPcheck = db.Users_RS2F_OTP.Where(t => t.OTP == ccc).ToList();
                if (OTPcheck.Count > 1)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            }
               
        }



     public   bool maintainlogofOTP( long userid, string Otp)
        {
            try
            {
                using (NPMDevDBEntities6 db = new NPMDevDBEntities6())
                {
                    Users_RS2F_OTP model = new Users_RS2F_OTP();
                    model.UserId = userid;
                    model.OTP = Convert.ToInt64(Otp);
                    model.ISEXPIRED = false;

                    var macAddr =
                                (
                                    from nic in NetworkInterface.GetAllNetworkInterfaces()
                                    where nic.OperationalStatus == OperationalStatus.Up
                                    select nic.GetPhysicalAddress().ToString()
                                ).FirstOrDefault();
                    model.MacAddress = macAddr;
                    model.IPAddress = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName()).AddressList.GetValue(0).ToString();
                    model.CreatedBy = userid;
                    model.CreatedDate = DateTime.Now;
                    model.ExpiredDate = DateTime.Now.AddMinutes(2);
                    model.ModifiedBy = null;
                    model.Attempts = 1;
                    model.ModifiedDate = null;
                    db.Users_RS2F_OTP.Add(model);
                    db.SaveChanges();
                }
                return true;
            }
            catch (Exception)
            {
                throw;

            }
           
            
        }



    }
}