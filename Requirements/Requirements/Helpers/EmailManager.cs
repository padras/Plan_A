namespace Requirements.Helpers
{
    using MailKit.Net.Smtp;
    using Microsoft.Extensions.Configuration;
    using MimeKit;

    public class EmailManager : IEmailManager
    {
        private readonly IConfiguration configuration;

        public EmailManager(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public void SendMail(string to, string subject, string body)
        {
            var from = configuration["Mail:From"];
            var smtp = configuration["Mail:Smtp"];
            var port = configuration["Mail:Port"];
            var password = configuration["Mail:Password"];

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(from));
            message.To.Add(new MailboxAddress(to));
            message.Subject = subject;
            var bodyBuilder = new BodyBuilder
            {
                HtmlBody = body
            };
            message.Body = bodyBuilder.ToMessageBody();

            using (var client = new SmtpClient())
            {
                client.Connect(smtp, int.Parse(port), false);
                client.Authenticate(from, password);
                client.Send(message);
                client.Disconnect(true);
            }
        }
    }
}
