using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using FluentEmail.Mailgun;
using FluentEmail.Core;

namespace okta_aspnetcore_mvc_example.Services
{

    public interface IEmailService 
    {
        Task<bool> SendEmail(string from, string to, string subject, string body);
    }


    public class EmailService : IEmailService
    {
        MailgunSender _sender = null;
        public EmailService()
        {
            _sender = new MailgunSender(
                    "mail.aclarkesylvania.com", // Mailgun Domain
                    "ec7f2e2b479823dca6bd5a8777f49954-ee13fadb-34652799" // Mailgun API Key
                    );

        }

        public async Task<bool> SendEmail(string from, string to, string subject, string body)
        {
            FluentEmail.Core.Email.DefaultSender = _sender;

            var email = FluentEmail.Core.Email
                .From(from)
                .To(to)
                .Subject(subject)
                .Body(body,true);  //bool isHtml= true
            //.Body("Core 3.1 content");

            var response = await email.SendAsync();


            return response.Successful;
        }

    }
}
