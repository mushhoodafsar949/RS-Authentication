﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace RS_Authentication_Server.Models
{
    using System;
    using System.Data.Entity;
    using System.Data.Entity.Infrastructure;
    using System.Data.Entity.Core.Objects;
    using System.Linq;
    
    public partial class NPMDevDBEntities6 : DbContext
    {
        public NPMDevDBEntities6()
            : base("name=NPMDevDBEntities6")
        {
        }
    
        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            throw new UnintentionalCodeFirstException();
        }
    
        public virtual DbSet<Users_RS2F_OTP> Users_RS2F_OTP { get; set; }
    
        public virtual ObjectResult<SP_authorization_Result> SP_authorization(string username)
        {
            var usernameParameter = username != null ?
                new ObjectParameter("Username", username) :
                new ObjectParameter("Username", typeof(string));
    
            return ((IObjectContextAdapter)this).ObjectContext.ExecuteFunction<SP_authorization_Result>("SP_authorization", usernameParameter);
        }
    
        public virtual ObjectResult<Nullable<int>> SP_CheckOTP_EXPIRY_Date(Nullable<long> pUserid, Nullable<long> pCode)
        {
            var pUseridParameter = pUserid.HasValue ?
                new ObjectParameter("pUserid", pUserid) :
                new ObjectParameter("pUserid", typeof(long));
    
            var pCodeParameter = pCode.HasValue ?
                new ObjectParameter("pCode", pCode) :
                new ObjectParameter("pCode", typeof(long));
    
            return ((IObjectContextAdapter)this).ObjectContext.ExecuteFunction<Nullable<int>>("SP_CheckOTP_EXPIRY_Date", pUseridParameter, pCodeParameter);
        }
    }
}
