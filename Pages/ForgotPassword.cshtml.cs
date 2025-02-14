using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;

namespace FreshFarmMarket.Pages
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailService _emailService;
        private readonly ILogger<ForgotPasswordModel> _logger;

        // Constructor to inject the necessary dependencies
        public ForgotPasswordModel(UserManager<ApplicationUser> userManager, IEmailService emailService, ILogger<ForgotPasswordModel> logger)
        {
            _userManager = userManager;
            _emailService = emailService;
            _logger = logger;
        }

        // Bind property for Email input from the form
        [BindProperty]
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email address.")]
        public string Email { get; set; }

        // Handle form submission
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                // Return to the same page if there are validation errors
                return Page();
            }

            // Look for user with the provided email
            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                // Log that the user was not found and redirect to confirmation page
                _logger.LogWarning("Forgot Password: Email {Email} not found.", Email);
                return RedirectToPage("/ForgotPasswordConfirmation");
            }

            // Generate a password reset token
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Generate the reset link (URL) with the token and email
            var resetLink = Url.Page("/ResetPassword", null, new { token, email = user.Email }, Request.Scheme);

            // Send the reset link via email
            await _emailService.SendEmailAsync(user.Email, "Reset Password", $"Click <a href='{resetLink}'>here</a> to reset your password.");

            // Log the email send operation
            _logger.LogInformation("Password reset link sent to {Email}.", user.Email);

            // Redirect to the confirmation page after the email is sent
            return RedirectToPage("/ForgotPasswordConfirmation");
        }
    }
}
