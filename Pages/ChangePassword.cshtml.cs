using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using FreshFarmMarket.Models;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using System;
using System.Collections.Generic;
using System.Text.Encodings.Web; // ✅ Import HtmlEncoder for sanitization

namespace FreshFarmMarket.Pages
{
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<ChangePasswordModel> _logger;

        public ChangePasswordModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ILogger<ChangePasswordModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [BindProperty]
        public ChangePasswordInputModel Input { get; set; }

        public string StatusMessage { get; set; }

        public class ChangePasswordInputModel
        {
            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Current Password")]
            public string CurrentPassword { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "New Password")]
            [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters.")]
            [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$",
                ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")]
            public string NewPassword { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Confirm New Password")]
            [Compare("NewPassword", ErrorMessage = "Passwords do not match.")]
            public string ConfirmNewPassword { get; set; }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // ✅ Get authenticated user
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                _logger.LogWarning("User session expired or unauthorized access attempt.");
                return RedirectToPage("/Login");
            }

            // ✅ Sanitize input to prevent XSS attacks
            Input.CurrentPassword = HtmlEncoder.Default.Encode(Input.CurrentPassword);
            Input.NewPassword = HtmlEncoder.Default.Encode(Input.NewPassword);
            Input.ConfirmNewPassword = HtmlEncoder.Default.Encode(Input.ConfirmNewPassword);

            // ✅ Check if current password is correct
            var passwordCheck = await _userManager.CheckPasswordAsync(user, Input.CurrentPassword);
            if (!passwordCheck)
            {
                _logger.LogWarning("User {UserEmail} entered incorrect current password.", user.Email);
                ModelState.AddModelError(string.Empty, "The current password is incorrect.");
                return Page();
            }

            // ✅ Enforce Minimum Password Age (Cannot change password too soon)
            int minPasswordAgeMinutes = 5; // Set to 5 mins for testing; adjust as needed
            if (user.LastPasswordChange.HasValue && DateTime.UtcNow < user.LastPasswordChange.Value.AddMinutes(minPasswordAgeMinutes))
            {
                ModelState.AddModelError(string.Empty, $"You cannot change your password within {minPasswordAgeMinutes} minutes of the last change.");
                return Page();
            }

            // ✅ Enforce Maximum Password Age (Must change password after X days)
            int maxPasswordAgeDays = 90; // Force change after 90 days
            if (user.LastPasswordChange.HasValue && DateTime.UtcNow > user.LastPasswordChange.Value.AddDays(maxPasswordAgeDays))
            {
                ModelState.AddModelError(string.Empty, "Your password has expired. You must change it now.");
                return Page();
            }

            // ✅ Prevent Password Reuse (Check last 2 passwords)
            int passwordHistoryLimit = 2;
            var passwordHasher = new PasswordHasher<ApplicationUser>();

            foreach (var oldPasswordHash in user.PasswordHistory)
            {
                if (passwordHasher.VerifyHashedPassword(user, oldPasswordHash, Input.NewPassword) == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError(string.Empty, "You cannot reuse your last two passwords.");
                    return Page();
                }
            }

            // ✅ Attempt password change
            var changePasswordResult = await _userManager.ChangePasswordAsync(user, Input.CurrentPassword, Input.NewPassword);
            if (!changePasswordResult.Succeeded)
            {
                foreach (var error in changePasswordResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return Page();
            }

            // ✅ Update password history (Keep only last 2 passwords)
            if (user.PasswordHistory == null)
            {
                user.PasswordHistory = new List<string>();
            }

            user.PasswordHistory.Add(user.PasswordHash); // Store previous password
            if (user.PasswordHistory.Count > passwordHistoryLimit)
            {
                user.PasswordHistory.RemoveAt(0); // Keep only last 2 passwords
            }

            // ✅ Update last password change timestamp
            user.LastPasswordChange = DateTime.UtcNow;

            await _userManager.UpdateAsync(user);
            await _signInManager.RefreshSignInAsync(user);

            _logger.LogInformation("User {UserEmail} changed their password successfully.", user.Email);

            StatusMessage = "Your password has been updated successfully.";

            return Page();
        }
    }
}
