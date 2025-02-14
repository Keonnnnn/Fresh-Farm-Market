using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Diagnostics;
using System.Diagnostics;

namespace FreshFarmMarket.Pages
{
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    [IgnoreAntiforgeryToken]
    public class ErrorModel : PageModel
    {
        private readonly ILogger<ErrorModel> _logger;

        public string? RequestId { get; set; }
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
        public int? StatusCode { get; set; }
        public string ErrorMessage { get; set; } = "An unexpected error occurred.";

        public ErrorModel(ILogger<ErrorModel> logger)
        {
            _logger = logger;
        }

        public void OnGet(int? statusCode = null)
        {
            RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
            StatusCode = statusCode;

            if (statusCode.HasValue)
            {
                switch (statusCode.Value)
                {
                    case 404:
                        ErrorMessage = "The page you are looking for was not found.";
                        break;
                    case 403:
                        ErrorMessage = "You do not have permission to access this page.";
                        break;
                    case 500:
                        ErrorMessage = "Internal server error. Please try again later.";
                        break;
                    default:
                        ErrorMessage = "An unexpected error occurred.";
                        break;
                }

                _logger.LogWarning("Error {StatusCode}: {ErrorMessage} (Request ID: {RequestId})",
                    StatusCode, ErrorMessage, RequestId);
            }
            else
            {
                _logger.LogError("Unknown error occurred. (Request ID: {RequestId})", RequestId);
            }
        }
    }
}
