using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using FreshFarmMarket.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.Cookies;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Logging;

var builder = WebApplication.CreateBuilder(args);

//  Register Google reCAPTCHA Service
builder.Services.AddHttpClient();
builder.Services.AddScoped<GoogleRecaptchaService>();

//  Register EmailService
builder.Services.AddScoped<IEmailService, EmailService>(); // Registering the EmailService for Dependency Injection

//  Add Razor Pages
builder.Services.AddRazorPages();

//  Configure Database Context
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AuthConnectionString"))
);

//  Configure Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password settings (Security Enhanced)
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 12;
    options.Password.RequiredUniqueChars = 1;

    // Lockout settings (Automatic Recovery)
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15); // Lockout duration
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.AllowedForNewUsers = true;

    // Enforce Password Age Policies
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedAccount = false;
})
.AddEntityFrameworkStores<AuthDbContext>()
.AddDefaultTokenProviders();

//  Configure Authentication Cookie (Hardened)
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.LoginPath = "/Login";
    options.AccessDeniedPath = "/AccessDenied";
    options.SlidingExpiration = true;
});

//  Configure Session (Security Hardened)
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

//  Add HSTS & HTTPS for Production
if (!builder.Environment.IsDevelopment())
{
    builder.Services.AddHsts(options =>
    {
        options.Preload = true;
        options.IncludeSubDomains = true;
        options.MaxAge = TimeSpan.FromDays(60);
    });
}

//  Configure Anti-Forgery Tokens
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

//  Configure Forwarded Headers for Reverse Proxy Support
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
});

//  Build the App
var app = builder.Build();

//  Configure Error Handling
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}
else
{
    app.UseDeveloperExceptionPage();
}

// ✅ Middleware Configuration
app.UseForwardedHeaders();
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseSession();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

//  Auto-Migrate Database & Create Admin User if Not Exists
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<AuthDbContext>();
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

        context.Database.Migrate(); // Apply any pending migrations

        //  Ensure Default Admin Role Exists
        var adminRole = "Admin";
        if (!await roleManager.RoleExistsAsync(adminRole))
        {
            await roleManager.CreateAsync(new IdentityRole(adminRole));
        }

        //  Ensure Default Admin User Exists
        var adminEmail = "admin@freshfarmmarket.com";
        var adminUser = await userManager.FindByEmailAsync(adminEmail);
        if (adminUser == null)
        {
            var newUser = new ApplicationUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                FullName = "Administrator",
                EmailConfirmed = true,
                LastPasswordChange = DateTime.UtcNow, // Set default password change time
                PasswordHistory = new List<string>() // Start with empty password history
            };

            var result = await userManager.CreateAsync(newUser, "Admin@1234");
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(newUser, adminRole);
            }
        }
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while migrating or initializing the database.");
    }
}


app.UseStatusCodePagesWithReExecute("/Error", "?statusCode={0}");
app.Run();
