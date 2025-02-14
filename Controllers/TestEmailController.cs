using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using FreshFarmMarket.Services;

namespace FreshFarmMarket.Controllers
{
    [ApiController]
    [Route("api/email")]
    public class TestEmailController : ControllerBase
    {
        private readonly IEmailService _emailService;

        public TestEmailController(IEmailService emailService)
        {
            _emailService = emailService;
        }

        [HttpGet("send-test")]
        public async Task<IActionResult> SendTestEmail()
        {
            await _emailService.SendEmailAsync("your-email@gmail.com", "Test Email", "This is a test email from Fresh Farm Market.");
            return Ok("Test email sent!");
        }
    }
}
