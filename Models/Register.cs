using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;  // Required for IFormFile

namespace FreshFarmMarket.Models
{
    public class Register
    {
        /// <summary>
        /// Full Name of the user.
        /// </summary>
        [Required(ErrorMessage = "Full Name is required.")]
        [StringLength(100, ErrorMessage = "Full Name cannot be longer than 100 characters.")]
        public string FullName { get; set; }

        /// <summary>
        /// Credit Card Number (Sensitive Data, should be encrypted before saving).
        /// Must be exactly 16 digits.
        /// </summary>
        [Required(ErrorMessage = "Credit Card Number is required.")]
        [RegularExpression(@"^\d{16}$", ErrorMessage = "Credit Card number must be exactly 16 digits.")]
        public string CreditCardNo { get; set; }

        /// <summary>
        /// User's gender selection.
        /// </summary>
        [Required(ErrorMessage = "Gender is required.")]
        public string Gender { get; set; }

        /// <summary>
        /// Mobile number with phone number validation.
        /// </summary>
        [Required(ErrorMessage = "Mobile Number is required.")]
        [Phone(ErrorMessage = "Invalid Phone Number.")]
        [RegularExpression(@"^\d{8,15}$", ErrorMessage = "Mobile number must be between 8 to 15 digits.")]
        public string MobileNo { get; set; }

        /// <summary>
        /// Delivery address.
        /// </summary>
        [Required(ErrorMessage = "Delivery Address is required.")]
        [StringLength(500, ErrorMessage = "Delivery Address cannot be longer than 500 characters.")]
        public string DeliveryAddress { get; set; }

        /// <summary>
        /// User email (must be valid email format).
        /// </summary>
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid Email Address.")]
        public string Email { get; set; }

        /// <summary>
        /// Password with a required length of at least 8 characters.
        /// </summary>
        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters long.")]
        public string Password { get; set; }

        /// <summary>
        /// Confirm Password field, must match the original password.
        /// </summary>
        [Required(ErrorMessage = "Confirm Password is required.")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }

        /// <summary>
        /// About Me section, required with a character limit.
        /// </summary>
        [Required(ErrorMessage = "About Me is required.")]
        [StringLength(500, ErrorMessage = "About Me section cannot exceed 500 characters.")]
        public string AboutMe { get; set; }

        /// <summary>
        /// Photo upload, only allows .jpg, .jpeg, and .png formats.
        /// </summary>
        [Required(ErrorMessage = "Please upload a photo.")]
        [DataType(DataType.Upload)]
        [AllowedFileExtensions(new string[] { ".jpg", ".jpeg", ".png" }, ErrorMessage = "Only JPG, JPEG, or PNG files are allowed.")]
        public IFormFile Photo { get; set; }
    }

    /// <summary>
    /// Custom validation attribute to check allowed file extensions.
    /// </summary>
    public class AllowedFileExtensionsAttribute : ValidationAttribute
    {
        private readonly string[] _extensions;

        public AllowedFileExtensionsAttribute(string[] extensions)
        {
            _extensions = extensions;
        }

        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            if (value is IFormFile file)
            {
                var fileExtension = Path.GetExtension(file.FileName).ToLowerInvariant();
                if (!_extensions.Contains(fileExtension))
                {
                    return new ValidationResult($"Only {string.Join(", ", _extensions)} files are allowed.");
                }
            }
            return ValidationResult.Success;
        }
    }
}