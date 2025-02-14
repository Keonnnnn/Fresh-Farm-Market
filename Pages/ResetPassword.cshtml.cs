using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using FreshFarmMarket.Models;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;

namespace FreshFarmMarket.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<ResetPasswordModel> _logger;

        public ResetPasswordModel(UserManager<ApplicationUser> userManager, ILogger<ResetPasswordModel> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        // Bind the Token and Email from the query string
        [BindProperty]
        public string Token { get; set; }

        [BindProperty]
        public string Email { get; set; }

        // New Password property with validation attributes
        [BindProperty]
        [Required]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; }

        // Confirm Password property with comparison to NewPassword
        [BindProperty]
        [Required]
        [DataType(DataType.Password)]
        [Compare("NewPassword", ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }

        // On GET method, bind the Token and Email from query string parameters
        public void OnGet(string email, string token)
        {
            Token = token;
            Email = email;
        }

        // On POST method, process password reset
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Find the user by email
            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                _logger.LogWarning("Invalid password reset attempt for {Email}.", Email);
                return RedirectToPage("/Login"); // Redirect to login page if user doesn't exist
            }

            // Reset password using the token and new password
            var result = await _userManager.ResetPasswordAsync(user, Token, NewPassword);
            if (result.Succeeded)
            {
                _logger.LogInformation("Password reset successful for {Email}.", Email);
                return RedirectToPage("/Login"); // Redirect to login page after successful reset
            }

            // Add errors if password reset failed
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page(); // Return the page if there are validation errors
        }
    }
}
