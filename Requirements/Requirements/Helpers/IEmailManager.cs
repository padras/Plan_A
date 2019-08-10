namespace Requirements.Helpers
{
    public interface IEmailManager
    {
        void SendMail(string to, string subject, string body);
    }
}
