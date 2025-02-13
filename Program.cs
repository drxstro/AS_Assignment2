using Asn2_AS.Data;
using Asn2_AS.Models;
using Asn2_AS.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Ensure the correct connection string is used
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AuthConnectionString")));

// Add Identity services
builder.Services.AddIdentity<User, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Configure session timeout & cookie options
builder.Services.ConfigureApplicationCookie(options =>
{
    options.ExpireTimeSpan = TimeSpan.FromSeconds(15); // Set cookie expiration to match session timeout
    options.SlidingExpiration = false; // Disable sliding expiration (keep it constant)
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.LoginPath = "/Account/Login"; // Redirect to Login if unauthorized
    options.AccessDeniedPath = "/Account/AccessDenied"; // Redirect to AccessDenied for unauthorized access

    options.Events.OnValidatePrincipal = async context =>
    {
        if (context.ShouldRenew)
        {
            context.RejectPrincipal(); // Reject the principal if the session expired
            await context.HttpContext.SignOutAsync(); // Force sign-out
            context.HttpContext.Response.Redirect("/Account/Login"); // Redirect to the login page
        }
    };
});


// Add session services
builder.Services.AddDistributedMemoryCache(); // Required for session storage
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromSeconds(15); // Set session idle timeout
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Add AuditLogService
builder.Services.AddScoped<AuditLogService>();

builder.Services.AddHttpClient(); 

builder.Services.AddControllersWithViews();

var app = builder.Build();

// Add custom middleware to prevent caching on login pages
app.Use(async (context, next) =>
{
    context.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate";
    context.Response.Headers["Pragma"] = "no-cache";
    context.Response.Headers["Expires"] = "0";
    await next();
});

// Ensure session middleware is added BEFORE authentication and authorization middlewares
app.UseSession(); // ✅ Ensure session middleware is added before authentication

// Session timeout middleware to handle non-login routes
app.Use(async (context, next) =>
{
    var controller = context.GetRouteData().Values["controller"]?.ToString();
    var action = context.GetRouteData().Values["action"]?.ToString();

    // Only check for timeout in non-login pages
    if (controller != "Account" || action != "Login")
    {
        var lastActivity = context.Session.GetString("LastActivity");
        if (!string.IsNullOrEmpty(lastActivity))
        {
            var lastActivityDate = DateTime.Parse(lastActivity);
            var timeElapsed = DateTime.Now - lastActivityDate;

            if (timeElapsed.TotalSeconds > 15) // Session timeout logic
            {
                context.Session.Clear(); // Clear session on timeout
                context.Response.Redirect("/Account/Login"); // Redirect to login
                return;
            }
        }
    }

    // Update session's last activity time on each request to reset the timeout
    context.Session.SetString("LastActivity", DateTime.Now.ToString("o"));

    // Continue processing the request
    await next.Invoke();
});

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication(); // Authentication middleware
app.UseAuthorization(); // Authorization middleware

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}");

app.Run();
