using FreshFarmMarket.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using FreshFarmMarket.Pages.Shared;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System;
using System.Collections.Generic;
using System.Text.Encodings.Web; // ✅ Import HtmlEncoder for sanitization

namespace FreshFarmMarket.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IConfiguration _configuration;

        public RegisterModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager,
            ILogger<RegisterModel> logger, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _configuration = configuration;
        }

        [BindProperty]
        [Required(ErrorMessage = "Full Name is required.")]
        [StringLength(100, ErrorMessage = "Full Name cannot be longer than 100 characters.")]
        public string FullName { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Credit Card Number is required.")]
        [RegularExpression(@"^\d{16}$", ErrorMessage = "Credit Card number must be exactly 16 digits.")]
        public string CreditCardNo { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Gender is required.")]
        public string Gender { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Mobile Number is required.")]
        [Phone(ErrorMessage = "Invalid Mobile Number.")]
        public string MobileNo { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Delivery Address is required.")]
        [StringLength(500, ErrorMessage = "Delivery Address cannot be longer than 500 characters.")]
        public string DeliveryAddress { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        public string Email { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters long.")]
        public string Password { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Confirm Password is required.")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "About Me is required.")]
        [StringLength(500, ErrorMessage = "About Me section cannot exceed 500 characters.")]
        public string AboutMe { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Please upload a photo.")]
        [DataType(DataType.Upload)]
        [ImageFile(new[] { ".jpg", ".jpeg", ".png" }, new[] { "image/jpeg", "image/png" }, ErrorMessage = "Only JPG, JPEG, or PNG files are allowed.")]
        public IFormFile Photo { get; set; }

        public void OnGet()
        {
            if (User.Identity?.IsAuthenticated ?? false)
            {
                Response.Redirect("/Index");
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Model state is invalid.");
                return Page();
            }

            // ✅ Sanitize inputs to prevent XSS
            FullName = HtmlEncoder.Default.Encode(FullName);
            AboutMe = HtmlEncoder.Default.Encode(AboutMe);
            DeliveryAddress = HtmlEncoder.Default.Encode(DeliveryAddress);

            // ✅ Check if email already exists
            var existingUser = await _userManager.FindByEmailAsync(Email);
            if (existingUser != null)
            {
                _logger.LogWarning("User with email {Email} already exists.", Email);
                ModelState.AddModelError(string.Empty, "This email is already registered.");
                return Page();
            }

            // ✅ Handle file upload securely
            string photoPath = null;
            if (Photo != null && Photo.Length > 0)
            {
                const long maxFileSize = 5 * 1024 * 1024;
                if (Photo.Length > maxFileSize)
                {
                    ModelState.AddModelError(string.Empty, "The file size exceeds the 5MB limit.");
                    return Page();
                }

                var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/uploads");
                if (!Directory.Exists(uploadsFolder))
                {
                    Directory.CreateDirectory(uploadsFolder);
                }

                var uniqueFileName = $"{Guid.NewGuid()}{Path.GetExtension(Photo.FileName)}";
                photoPath = Path.Combine("uploads", uniqueFileName);

                var filePath = Path.Combine(uploadsFolder, uniqueFileName);
                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await Photo.CopyToAsync(stream);
                }
            }

            // ✅ Encrypt the Credit Card Number
            var encryptedCreditCardNo = EncryptCreditCardNumber(CreditCardNo);

            // ✅ Create user and set security properties
            var user = new ApplicationUser
            {
                UserName = Email,
                Email = Email,
                FullName = FullName,
                AboutMe = AboutMe,
                ProfilePhotoPath = photoPath,
                Gender = Gender,
                MobileNo = MobileNo,
                DeliveryAddress = DeliveryAddress,
                CreditCardNo = encryptedCreditCardNo,
                LastPasswordChange = DateTime.UtcNow, // ✅ Initialize password change timestamp
                PasswordHistory = new List<string>() // ✅ Initialize empty password history
            };

            var result = await _userManager.CreateAsync(user, Password);
            if (result.Succeeded)
            {
                _logger.LogInformation("User created successfully.");

                // ✅ Store first password in history
                var passwordHasher = new PasswordHasher<ApplicationUser>();
                user.PasswordHistory.Add(passwordHasher.HashPassword(user, Password));

                await _userManager.UpdateAsync(user);
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToPage("Index");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page();
        }

        private string EncryptCreditCardNumber(string creditCardNumber)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.GenerateKey();
                aesAlg.GenerateIV();

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(creditCardNumber);
                    }
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }
    }
}
