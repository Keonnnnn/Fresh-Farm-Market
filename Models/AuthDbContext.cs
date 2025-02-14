using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace FreshFarmMarket.Models
{
    // ✅ Custom User Model with additional properties
    public class ApplicationUser : IdentityUser
    {
        public string FullName { get; set; }
        public string AboutMe { get; set; } = "Welcome to Fresh Farm Market!"; // ✅ Default Value
        public string ProfilePhotoPath { get; set; } = "/uploads/default-profile.png"; // ✅ Default Image
        public string CreditCardNo { get; set; } = "EncryptedDefaultCC"; // ✅ Default placeholder
        public string Gender { get; set; }
        public string MobileNo { get; set; }
        public string DeliveryAddress { get; set; }

        // ✅ Security Features
        public override string SecurityStamp { get; set; } = "default-security-stamp";

        // ✅ AES Encryption properties
        public string EncryptionKey { get; set; } = "default-encryption-key";
        public string EncryptionIV { get; set; } = "default-encryption-iv";

        // ✅ Password Policy Properties
        public DateTime? LastPasswordChange { get; set; } // Track last password change timestamp
        public List<string> PasswordHistory { get; set; } = new List<string>(); // Stores last 2 passwords
    }

    public class AuthDbContext : IdentityDbContext<ApplicationUser, IdentityRole, string>
    {
        private readonly IConfiguration _configuration;

        public AuthDbContext(DbContextOptions<AuthDbContext> options, IConfiguration configuration) : base(options)
        {
            _configuration = configuration;
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<ApplicationUser>(entity =>
            {
                entity.ToTable("Users");

                entity.Property(u => u.FullName).HasMaxLength(100);
                entity.Property(u => u.AboutMe).HasMaxLength(500).HasDefaultValue("Welcome to Fresh Farm Market!");
                entity.Property(u => u.ProfilePhotoPath).HasMaxLength(200).HasDefaultValue("/uploads/default-profile.png");
                entity.Property(u => u.CreditCardNo).HasMaxLength(256).HasDefaultValue("EncryptedDefaultCC");
                entity.Property(u => u.Gender).HasMaxLength(50);
                entity.Property(u => u.MobileNo).HasMaxLength(15);
                entity.Property(u => u.DeliveryAddress).HasMaxLength(500);

                // ✅ Prevent migration errors by setting a fixed SecurityStamp
                entity.Property(u => u.SecurityStamp)
                      .HasMaxLength(256)
                      .HasDefaultValue("default-security-stamp");

                entity.Property(u => u.EncryptionKey).HasMaxLength(256).HasDefaultValue("default-encryption-key");
                entity.Property(u => u.EncryptionIV).HasMaxLength(128).HasDefaultValue("default-encryption-iv");

                // ✅ Password Policy Enforcement Fields
                entity.Property(u => u.LastPasswordChange)
                      .HasColumnType("datetime2");

                entity.Property(u => u.PasswordHistory)
                      .HasConversion(
                          v => string.Join(";", v), // Convert list to a string for storage
                          v => v.Split(';', StringSplitOptions.RemoveEmptyEntries).ToList()); // Convert back to list
            });

            builder.Entity<IdentityRole>(entity =>
            {
                entity.ToTable("Roles");
            });

            // ✅ Seed Default Admin User (Static Values)
            builder.Entity<ApplicationUser>().HasData(new ApplicationUser
            {
                Id = "b3e3c1d0-5c24-44a1-91cb-98b66b5e6f4d",  // ✅ Static ID
                UserName = "admin@freshfarmmarket.com",
                Email = "admin@freshfarmmarket.com",
                FullName = "Admin User",
                AboutMe = "Administrator of Fresh Farm Market",
                SecurityStamp = "a1b2c3d4e5f6g7h8i9j0",
                PasswordHash = "AQAAAAEAACcQAAAAEJ4m+NwMtrszXt5==",
                Gender = "Not Specified",
                MobileNo = "1234567890",
                DeliveryAddress = "Admin Office",
                ProfilePhotoPath = "/uploads/default-profile.png",
                CreditCardNo = "EncryptedDefaultCC",
                EncryptionKey = "your-base64-encoded-key",
                EncryptionIV = "your-base64-encoded-IV",
                LastPasswordChange = DateTime.UtcNow, // Default password change time
                PasswordHistory = new List<string>() // Empty password history initially
            });
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.ConfigureWarnings(warnings =>
                warnings.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.RelationalEventId.PendingModelChangesWarning));
        }

        // ✅ Secure Encryption Helper
        public static class EncryptionHelper
        {
            private static string Key => GetValidBase64String(
                Environment.GetEnvironmentVariable("ENCRYPTION_KEY") ?? "your-base64-encoded-key"
            );

            private static string Iv => GetValidBase64String(
                Environment.GetEnvironmentVariable("ENCRYPTION_IV") ?? "your-base64-encoded-IV"
            );

            private static string GetValidBase64String(string input)
            {
                if (string.IsNullOrEmpty(input))
                    throw new ArgumentException("Encryption key/IV cannot be null or empty.");

                input = input.Trim();

                if (!IsValidBase64(input))
                    throw new FormatException("Invalid Base64 format in encryption key/IV.");

                return input;
            }

            private static bool IsValidBase64(string str)
            {
                if (string.IsNullOrEmpty(str))
                    return false;

                str = str.Trim();
                return (str.Length % 4 == 0) &&
                       Regex.IsMatch(str, @"^[a-zA-Z0-9\+/]*={0,2}$");
            }

            public static string Encrypt(string plainText)
            {
                if (string.IsNullOrEmpty(plainText))
                    throw new ArgumentException("Plain text cannot be null or empty.");

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Convert.FromBase64String(Key);
                    aesAlg.IV = Convert.FromBase64String(Iv);

                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        return Convert.ToBase64String(msEncrypt.ToArray());
                    }
                }
            }

            public static string Decrypt(string cipherText)
            {
                if (string.IsNullOrEmpty(cipherText))
                    throw new ArgumentException("Cipher text cannot be null or empty.");

                cipherText = cipherText.Trim();
                if (!IsValidBase64(cipherText))
                    throw new FormatException("Invalid Base64 format in cipher text.");

                while (cipherText.Length % 4 != 0)
                {
                    cipherText += "=";
                }

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Convert.FromBase64String(Key);
                    aesAlg.IV = Convert.FromBase64String(Iv);

                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }
}
