using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace FreshFarmMarket.Pages
{
    public class LoginWith2faModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<LoginWith2faModel> _logger;
        private readonly IEmailService _emailService;

        public LoginWith2faModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            ILogger<LoginWith2faModel> logger,
            IEmailService emailService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
            _emailService = emailService;
        }

        [BindProperty]
        public TwoFactorInputModel Input { get; set; } = new TwoFactorInputModel();

        [TempData]
        public string? ErrorMessage { get; set; }

        public string Token { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;

        public class TwoFactorInputModel
        {
            [Required(ErrorMessage = "Please enter your authentication code.")]
            [StringLength(6, ErrorMessage = "The authentication code must be 6 digits.", MinimumLength = 6)]
            [RegularExpression(@"^\d{6}$", ErrorMessage = "Invalid code format. It must be exactly 6 digits.")]
            public string TwoFactorCode { get; set; } = string.Empty;
        }

        public async Task<IActionResult> OnGetAsync(string? returnUrl = null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                _logger.LogWarning("2FA attempt failed: User not found.");
                return RedirectToPage("/Login");
            }

            //  Generate & send 2FA code
            await SendTwoFactorCodeAsync(user);

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                _logger.LogWarning("2FA login attempt failed: User not found.");
                return RedirectToPage("/Login");
            }

            var result = await _signInManager.TwoFactorSignInAsync("Email", Input.TwoFactorCode, isPersistent: false, rememberClient: false);
            if (result.Succeeded)
            {
                _logger.LogInformation("2FA successful for {UserName}.", user.UserName);
                return RedirectToPage(returnUrl ?? "/Index");
            }

            _logger.LogWarning("Invalid 2FA code for {UserName}.", user.UserName);
            ModelState.AddModelError(string.Empty, "Invalid verification code.");
            return Page();
        }

        public async Task<IActionResult> OnPostResendAsync()
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                _logger.LogWarning("2FA resend attempt failed: User not found.");
                return RedirectToPage("/Login");
            }

            //  Resend 2FA code
            await SendTwoFactorCodeAsync(user);
            _logger.LogInformation("Resent 2FA code to {Email}.", user.Email);
            return RedirectToPage();
        }

        private async Task SendTwoFactorCodeAsync(ApplicationUser user)
        {
            Token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
            if (string.IsNullOrEmpty(Token))
            {
                _logger.LogWarning("Failed to generate 2FA code for {UserName}.", user.UserName);
                return;
            }

            Email = user.Email;
            var subject = "Your Fresh Farm Market 2FA Code";
            var message = $"Hello {user.FullName},<br><br>Your authentication code is: <strong>{Token}</strong>.<br><br>If you did not request this, please ignore this email.";

            await _emailService.SendEmailAsync(user.Email, subject, message);
            _logger.LogInformation("2FA code sent to {Email}.", user.Email);
        }
    }
}
