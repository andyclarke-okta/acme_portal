using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace okta_aspnetcore_mvc_example.Models
{
    public class RegisterUser
    {
        public string email { get; set; }
        public string password { get; set; }
        public string firstName { get; set; }
        public string lastName { get; set; }
        public string hasOptedOutGeoTracking { get; set; }
        public string hasOptedOutProfiling { get; set; }
        public string hasOptedOutTracking { get; set; }
        public string hasOptedOutProcessing { get; set; }
        public string hasOptedOutSolicit { get; set; }
        public string customId { get; set; }

    }
}
