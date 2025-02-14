using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using FreshFarmMarket.Models;  // Ensure this namespace includes your ApplicationUser class
using System.Threading.Tasks;
using static FreshFarmMarket.Models.AuthDbContext;

namespace FreshFarmMarket.Pages
{
    [AllowAnonymous] // Allows unauthenticated users to access the home page (remove if login is required)
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly UserManager<ApplicationUser> _userManager;

        // Constructor to inject the logger and UserManager
        public IndexModel(ILogger<IndexModel> logger, UserManager<ApplicationUser> userManager)
        {
            _logger = logger;
            _userManager = userManager;
        }

        public ApplicationUser CurrentUser { get; set; }
        public string DecryptedCreditCardNo { get; set; }

        // Handles GET request to load the Index page
        public async Task<IActionResult> OnGetAsync()
        {
            _logger.LogInformation("Home page loaded successfully.");

            // Check if the user is authenticated
            if (User.Identity.IsAuthenticated)
            {
                // Get the logged-in user from the database
                CurrentUser = await _userManager.GetUserAsync(User);

                if (CurrentUser != null && !string.IsNullOrEmpty(CurrentUser.CreditCardNo))
                {
                    try
                    {
                        // Decrypt the stored credit card number
                        DecryptedCreditCardNo = EncryptionHelper.Decrypt(CurrentUser.CreditCardNo);
                        _logger.LogInformation("Credit card number decrypted successfully.");
                    }
                    catch (System.FormatException ex)
                    {
                        _logger.LogError($"Decryption failed: Invalid Base64 format - {ex.Message}");
                        DecryptedCreditCardNo = "Invalid stored data.";
                    }
                    catch (System.Exception ex)
                    {
                        _logger.LogError($"Unexpected error during decryption: {ex.Message}");
                        DecryptedCreditCardNo = "Error decrypting card.";
                    }
                }
                else
                {
                    DecryptedCreditCardNo = "No credit card information available.";
                }
            }

            return Page();
        }
    }
}