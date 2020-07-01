using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace okta_aspnetcore_mvc_example.Models
{
    public class TokenRequestResponse
    {
        public string error { get; set; }
        public string error_description { get; set; }
        public string errorCode { get; set; }
        public string errorSummary { get; set; }
        public List<errorCauses> errorCauses { get; set; }
        public string access_token { get; set; }
        public string token_type { get; set; }
        public string expires_in { get; set; }
        public string scope { get; set; }
        public string id_token { get; set; }
        public string refresh_token { get; set; }
    }

    public class errorCauses
    {
        public string errorSummary { get; set; }
    }
}
