using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Authentication;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using System;
using System.Text.Encodings.Web; //  Import HtmlEncoder for sanitization

namespace FreshFarmMarket.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<LoginModel> _logger;
        private readonly GoogleRecaptchaService _recaptchaService;
        private readonly IConfiguration _configuration;

        public LoginModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            ILogger<LoginModel> logger,
            GoogleRecaptchaService recaptchaService,
            IConfiguration configuration)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
            _recaptchaService = recaptchaService;
            _configuration = configuration;
        }

        [BindProperty]
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email address.")]
        public string Email { get; set; } = string.Empty;

        [BindProperty]
        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [BindProperty]
        public bool RememberMe { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "reCAPTCHA validation is required.")]
        public string RecaptchaToken { get; set; } = string.Empty;

        public string ReCaptchaSiteKey => _configuration["GoogleReCaptcha:SiteKey"];

        [TempData]
        public string? ErrorMessage { get; set; }

        public async Task<IActionResult> OnGetAsync(string? returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            //  Clear any external authentication cookies before login
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            if (User.Identity?.IsAuthenticated ?? false)
            {
                return RedirectToPage("/Index");
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            if (!ModelState.IsValid)
            {
                return Page();
            }

            //  Sanitize input to prevent XSS attacks
            Email = HtmlEncoder.Default.Encode(Email);

            //  Verify Google reCAPTCHA Score (Anti-bot protection)
            double thresholdScore = 0.5;
            var recaptchaScore = await _recaptchaService.VerifyCaptchaAsync(RecaptchaToken);

            if (!recaptchaScore.HasValue || recaptchaScore.Value < thresholdScore)
            {
                _logger.LogWarning("reCAPTCHA verification failed due to low score for email: {Email}.", Email);
                ModelState.AddModelError(string.Empty, "Suspicious activity detected. Please try again.");
                return Page();
            }

            //  Find user by email
            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                _logger.LogWarning("Invalid login attempt for email: {Email}.", Email);
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return Page();
            }

            //  Check if the account is locked
            if (await _userManager.IsLockedOutAsync(user))
            {
                var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
                if (lockoutEnd.HasValue && lockoutEnd.Value < DateTimeOffset.UtcNow)
                {
                    //  Auto Unlock after lockout period
                    await _userManager.SetLockoutEndDateAsync(user, null);
                    await _userManager.ResetAccessFailedCountAsync(user);
                    _logger.LogInformation("User {Email} lockout period expired. Account unlocked.", Email);
                }
                else
                {
                    _logger.LogWarning("User {Email} is locked out.", Email);
                    ModelState.AddModelError(string.Empty, "Your account is locked. Please try again later.");
                    return Page();
                }
            }

            //  Enforce Password Expiration Policy (e.g., 90 days)
            int maxPasswordAgeDays = 90;
            if (user.LastPasswordChange.HasValue && DateTime.UtcNow > user.LastPasswordChange.Value.AddDays(maxPasswordAgeDays))
            {
                _logger.LogInformation("User {Email} must change password due to expiration.", Email);
                return RedirectToPage("/ChangePassword", new { expired = true });
            }

            //  Attempt login
            var result = await _signInManager.PasswordSignInAsync(user.UserName, Password, RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                _logger.LogInformation("User {Email} logged in successfully.", Email);
                return LocalRedirect(returnUrl);
            }

            if (result.RequiresTwoFactor)
            {
                return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe });
            }

            if (result.IsLockedOut)
            {
                _logger.LogWarning("User {Email} account locked out.", Email);
                ModelState.AddModelError(string.Empty, "Account has been locked out. Please try again later.");
                return Page();
            }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return Page();
        }

        public async Task<IActionResult> OnPostLogoutAsync()
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");
            return RedirectToPage("/Index");
        }
    }
}