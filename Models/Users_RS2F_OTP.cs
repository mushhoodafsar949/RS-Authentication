//------------------------------------------------------------------------------
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
    using System.Collections.Generic;
    
    public partial class Users_RS2F_OTP
    {
        public int UserOTPId { get; set; }
        public long OTP { get; set; }
        public Nullable<long> UserId { get; set; }
        public Nullable<bool> VerificationStatus { get; set; }
        public Nullable<bool> ISEXPIRED { get; set; }
        public Nullable<bool> IsDeleted { get; set; }
        public Nullable<long> CreatedBy { get; set; }
        public Nullable<System.DateTimeOffset> CreatedDate { get; set; }
        public Nullable<System.DateTimeOffset> ExpiredDate { get; set; }
        public Nullable<System.DateTimeOffset> ModifiedDate { get; set; }
        public Nullable<long> ModifiedBy { get; set; }
        public string MacAddress { get; set; }
        public string IPAddress { get; set; }
        public Nullable<int> Attempts { get; set; }
    }
}
