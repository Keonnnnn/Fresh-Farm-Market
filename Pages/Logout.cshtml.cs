using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using System.Threading.Tasks;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;

namespace FreshFarmMarket.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<LogoutModel> _logger;
        private readonly IConfiguration _configuration;

        // Inject dependencies, without reCAPTCHA service
        public LogoutModel(
            SignInManager<ApplicationUser> signInManager,
            ILogger<LogoutModel> logger,
            IConfiguration configuration)
        {
            _signInManager = signInManager;
            _logger = logger;
            _configuration = configuration;
        }

        public IActionResult OnGet()
        {
            // Prevent unnecessary logout attempts when already logged out
            if (!User.Identity?.IsAuthenticated ?? true)
            {
                _logger.LogWarning("Unauthorized logout attempt or user already logged out.");
                return RedirectToPage("/Login");
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // Check if the user is authenticated
            if (User.Identity?.IsAuthenticated ?? false)
            {
                string userEmail = User.Identity?.Name ?? "Unknown User";
                string userIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown IP";

                // Clear session BEFORE signing out (prevents session persistence issues)
                HttpContext.Session.Clear();

                await _signInManager.SignOutAsync();  // Log the user out

                _logger.LogInformation("User {Email} successfully logged out from {IP}.", userEmail, userIp);
            }
            else
            {
                _logger.LogWarning("Logout attempt by an unauthenticated user.");
            }

            // Redirect to login page after logout to prevent resubmission issues
            return RedirectToPage("/Login");
        }
    }
}
