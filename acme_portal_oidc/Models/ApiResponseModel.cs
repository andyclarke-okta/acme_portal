using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace okta_aspnetcore_mvc_example.Models
{
    

public class ApiResponseModel
{
        public List<Message> messages { get; set; }
    }

    public class Message
    {
        public string date { get; set; }
        public string text { get; set; }
    }

    public class Record
    {
        public int Id { get; set; }
        public string RecordName { get; set; }

        public string RecordDetail { get; set; }
    }

}
