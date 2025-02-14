using System.Threading.Tasks;

namespace FreshFarmMarket.Services
{
    // Interface for the EmailService
    public interface IEmailService
    {
        // Method to send an email asynchronously
        Task SendEmailAsync(string to, string subject, string body);
    }
}
