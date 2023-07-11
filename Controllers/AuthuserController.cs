using System;
using RS_Authentication_Server.Models.ViewModel;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using RS_Authentication_Server.Models;
using RS_Authentication_Server.Services;
using System.IO;
using System.Web;
using IdentityModel.Client;

namespace RS_Authentication_Server.Controllers
{
    public class AuthuserController : ApiController
    {
        private readonly UserAuthService _userAuthService;
        public AuthuserController(UserAuthService obj)
        {
            _userAuthService = obj;
        }



        NPMDevDBEntities6 nde = new NPMDevDBEntities6();

        [AllowAnonymous]
        public IHttpActionResult Auth([FromBody] TokenRequestModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(string.Join(";", ModelState.Values.SelectMany(e => e.Errors).Select(e => e.ErrorMessage)));
            }
            switch (model.Grant_Type)
            {
                case "password":
                    return CreateAccessToken(model);
                case "refresh_token":
                    return RefreshToken(model);
                default:
                    return BadRequest("Invalid grant type");
            }
        }

        [HttpPost]
        public HttpResponseMessage myauthfunc(loginViewModel loginView)
        {

            try
            {
                if (loginView.username == null && loginView.password == null)
                {
                    return Request.CreateResponse(HttpStatusCode.NotAcceptable, "Email and Password is null");
                }

                List<SP_authorization_Result> authoruser = new List<SP_authorization_Result>();
                authoruser = nde.SP_authorization(loginView.username).ToList();

                if (authoruser.Count == 0)
                {
                    return Request.CreateResponse(HttpStatusCode.NotFound, "User not Registered");
                }
                else
                {
                    foreach (var user in authoruser)
                    {
                        var check = _userAuthService.VerifyHashedPassword(user.Password, loginView.password);
                        if (loginView.username == user.Username && check == true)
                        {
                            var OTP = _userAuthService.myauthmailsender(user.Email, user.LastName);

                            if (OTP != null && OTP != "")
                            {
                                var status = _userAuthService.maintainlogofOTP(user.UserId, OTP);
                                if (status == true)
                                {
                                    return Request.CreateResponse(HttpStatusCode.OK, HttpStatusCode.OK.ToString() + check);
                                }
                                else
                                {
                                    return Request.CreateResponse(HttpStatusCode.Forbidden, "Failed to save Credentials. Status: " + status);
                                }

                            }

                            else
                            {
                                return Request.CreateResponse(HttpStatusCode.NotFound, "NULL OTP. Status: " + check);
                            }


                        }
                        else
                        {
                            return Request.CreateResponse(HttpStatusCode.NotFound, "User not found. Status: " + check);
                        }

                    }
                    return Request.CreateResponse(HttpStatusCode.BadRequest, "User not found");
                }


            }
            catch (Exception ex)
            {
                return Request.CreateResponse(HttpStatusCode.InternalServerError, ex.Message);
            }



        }



        [HttpPost]
        public HttpResponseMessage myemailverification(Emailverification code)
        {
            try
            {

                if (code.verificationcode != null)
                {


                    var uniquecode = _userAuthService.checkforDuplication(code.verificationcode);
                    if (uniquecode != false)
                    {
                        long ccc = Convert.ToInt64(code.verificationcode);
                        var verification = nde.Users_RS2F_OTP.Where(t => t.OTP == ccc).ToList();

                        if (verification.Count > 0)
                        {

                            foreach (var ver in verification)
                            {

                                if (ver.ISEXPIRED == false && ver.VerificationStatus == null)
                                {

                                    List<Nullable<int>> expirydate = null;
                                    expirydate = nde.SP_CheckOTP_EXPIRY_Date(ver.UserId, ver.OTP).ToList();
                                    if (expirydate.Count > 0)
                                    {
                                        foreach (var exp in expirydate)
                                        {
                                            if (exp != 1 && ver.ISEXPIRED == false && ver.VerificationStatus == null)
                                            {
                                                ver.VerificationStatus = true;
                                                // ver.ISEXPIRED = true;
                                                nde.Entry(ver).CurrentValues.SetValues(ver);
                                                nde.SaveChanges();
                                                return Request.CreateResponse(HttpStatusCode.OK, " OTP Verified");
                                            }
                                            else
                                            {
                                                ver.ISEXPIRED = true;
                                                nde.Entry(ver).CurrentValues.SetValues(ver);
                                                nde.SaveChanges();
                                                return Request.CreateResponse(HttpStatusCode.Unauthorized, " OTP Expired");
                                            }
                                        }
                                    }
                                    else
                                    {
                                        return Request.CreateResponse(HttpStatusCode.Gone, "OTP TIME IS EXPIRED");
                                    }

                                }
                                else
                                {
                                    return Request.CreateResponse(HttpStatusCode.Forbidden, " OTP Expired");
                                }

                            }
                            return Request.CreateResponse(HttpStatusCode.OK, "User Is Valid");
                        }
                        else
                        {
                            return Request.CreateResponse(HttpStatusCode.Gone, "OTP EXISTS, BUT EXPIRED");
                        }
                    }
                    else
                    {
                        return Request.CreateResponse(HttpStatusCode.Ambiguous, "OTP IS USED, ALREADY EXISTS!");
                    }


                }

                else
                {
                    return Request.CreateResponse(HttpStatusCode.NoContent, "OTP FOUND NULL");
                }

            }
            catch (Exception ex)
            {
                return Request.CreateResponse(HttpStatusCode.InternalServerError, ex.Message);
            }
        }

    }
}




