using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;
using System;
using System.IO;
using System.Linq;

namespace FreshFarmMarket.Pages.Shared
{
    public class ImageFileAttribute : ValidationAttribute
    {
        private readonly string[] _extensions;
        private readonly string[] _mimeTypes;
        private readonly long _maxFileSize; // Max file size in bytes

        public ImageFileAttribute(string[] extensions, string[] mimeTypes, long maxFileSize = 5 * 1024 * 1024) // Default max size 5MB
        {
            _extensions = extensions;
            _mimeTypes = mimeTypes;
            _maxFileSize = maxFileSize;
        }

        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            var file = value as IFormFile;

            if (file == null || file.Length == 0)
            {
                return new ValidationResult("Please upload a photo.");
            }

            // Check file extension
            var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
            if (!_extensions.Contains(extension))
            {
                return new ValidationResult($"Only {string.Join(", ", _extensions)} files are allowed.");
            }

            // Check MIME type
            if (!_mimeTypes.Contains(file.ContentType))
            {
                return new ValidationResult("Invalid file type.");
            }

            // Check file size
            if (file.Length > _maxFileSize)
            {
                return new ValidationResult($"The file size exceeds the maximum limit of {FormatBytes(_maxFileSize)}.");
            }

            return ValidationResult.Success;
        }

        // Helper method to format file size in human-readable form
        private string FormatBytes(long bytes)
        {
            string[] suffix = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order + 1 < suffix.Length)
            {
                order++;
                len = len / 1024;
            }
            return string.Format("{0:0.##} {1}", len, suffix[order]);
        }
    }
}