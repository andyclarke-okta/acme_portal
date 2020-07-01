using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace okta_aspnetcore_mvc_example.Models
{
    public class EmailViewModel
    {
        public string OktaId { get; set; }
        public string Name { get; set; }
        public string LinkExpiry { get; set; }
        public string AcceptToken { get; set; }

        public string RejectToken { get; set; }

        public string BasePath { get; set; }

    }
}
