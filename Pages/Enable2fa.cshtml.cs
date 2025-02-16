using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using FreshFarmMarket.Models;
using System.Threading.Tasks;

namespace FreshFarmMarket.Pages
{
    public class Enable2FAModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<Enable2FAModel> _logger;

        public Enable2FAModel(UserManager<ApplicationUser> userManager, ILogger<Enable2FAModel> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        public bool IsTwoFactorEnabled { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToPage("/Login");

            IsTwoFactorEnabled = user.TwoFactorEnabled;
            return Page();
        }

        public async Task<IActionResult> OnPostEnableAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToPage("/Login");

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            _logger.LogInformation("User enabled 2FA.");
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostDisableAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToPage("/Login");

            await _userManager.SetTwoFactorEnabledAsync(user, false);
            _logger.LogInformation("User disabled 2FA.");
            return RedirectToPage();
        }
    }
}
