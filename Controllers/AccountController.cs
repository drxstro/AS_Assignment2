using Asn2_AS.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System;
using System.Collections.Generic;
using Asn2_AS.Services;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using System.Text.Encodings.Web;
using Microsoft.EntityFrameworkCore;
using Asn2_AS.Data;

namespace Asn2_AS.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;

        private readonly ApplicationDbContext _dbContext;
        private readonly AuditLogService _auditLogService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly IAntiforgery _antiforgery;
        private static readonly Dictionary<string, string> ActiveSessions = new();
        private static readonly Dictionary<string, int> FailedLoginAttempts = new();
        private static readonly Dictionary<string, DateTime> AccountLockouts = new();

        public AccountController(UserManager<User> userManager, SignInManager<User> signInManager, ApplicationDbContext dbContext, IHttpContextAccessor httpContextAccessor,
                                 AuditLogService auditLogService, IHttpClientFactory httpClientFactory, IConfiguration configuration, IAntiforgery antiforgery)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _dbContext = dbContext;
            _httpContextAccessor = httpContextAccessor;
            _auditLogService = auditLogService;
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _antiforgery = antiforgery;
        }

        private async Task<bool> VerifyReCaptchaAsync(string recaptchaResponse, string action)
        {
            var client = _httpClientFactory.CreateClient();
            var secretKey = "6LeRWtMqAAAAAHjH0YfYPW3jBORhwNq-gHMuMkJQ"; // Ensure this is a v3 key
            var verificationUrl = "https://www.google.com/recaptcha/api/siteverify";

            var response = await client.PostAsync(verificationUrl, new FormUrlEncodedContent(new Dictionary<string, string>
    {
        { "secret", secretKey },
        { "response", recaptchaResponse }
    }));

            var jsonResponse = await response.Content.ReadAsStringAsync();
            var jsonDoc = JsonDocument.Parse(jsonResponse);

            bool success = jsonDoc.RootElement.GetProperty("success").GetBoolean();
            float score = jsonDoc.RootElement.GetProperty("score").GetSingle();
            string responseAction = jsonDoc.RootElement.GetProperty("action").GetString();

            return success && score >= 0.5f && responseAction == action; // Ensure the action matches
        }



        [HttpGet]
        public IActionResult Register()
        {
            ViewData["CsrfToken"] = _antiforgery.GetAndStoreTokens(HttpContext).RequestToken;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string gRecaptchaResponse)
        {
            if (!ModelState.IsValid) return View(model);

            if (!await VerifyReCaptchaAsync(gRecaptchaResponse, "register"))
            {
                ModelState.AddModelError("", "reCAPTCHA verification failed.");
                return View(model);
            }

            if (await _userManager.FindByEmailAsync(model.Email) != null)
            {
                ModelState.AddModelError("", "Email already exists. Please try logging in.");
                return View(model);
            }

            if (model.DateOfBirth > DateTime.Now)
            {
                ModelState.AddModelError("DateOfBirth", "Date of birth cannot be in the future.");
                return View(model);
            }
            else if (DateTime.Now.Year - model.DateOfBirth.Year < 18)
            {
                ModelState.AddModelError("DateOfBirth", "User must be at least 18 years old.");
                return View(model);
            }

            if (model.Resume != null)
            {
                var fileExtension = Path.GetExtension(model.Resume.FileName).ToLower();
                if (fileExtension != ".pdf" && fileExtension != ".docx")
                {
                    ModelState.AddModelError("Resume", "Invalid file format. Please upload a PDF or DOCX file.");
                    return View(model);
                }
                if (model.Resume.Length > 2 * 1024 * 1024) // 2MB limit
                {
                    ModelState.AddModelError("Resume", "File size should not exceed 2MB.");
                    return View(model);
                }
            }

            var user = new User
            {
                FirstName = HtmlEncoder.Default.Encode(model.FirstName),
                LastName = HtmlEncoder.Default.Encode(model.LastName),
                Gender = HtmlEncoder.Default.Encode(model.Gender),
                EncryptedNRIC = Encrypt(model.NRIC),
                UserName = model.Email,
                Email = model.Email,
                DateOfBirth = model.DateOfBirth,
                WhoAmI = HtmlEncoder.Default.Encode(model.WhoAmI)
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                await _auditLogService.LogActivity(user.Id, "User registered.");
                SetSession(user);
                return RedirectToAction("Index", "Home");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
            return View(model);
        }

        [HttpGet]
        public IActionResult Login()
        {
            ViewData["CsrfToken"] = _antiforgery.GetAndStoreTokens(HttpContext).RequestToken;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string gRecaptchaResponse)
        {
            if (!ModelState.IsValid) return View(model);

            if (!await VerifyReCaptchaAsync(gRecaptchaResponse, "login"))
            {
                ModelState.AddModelError("", "reCAPTCHA verification failed.");
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Display a generic invalid login message for both incorrect email and password
                ModelState.AddModelError("", "Either your password or email is invalid. Please try again.");
                return View(model);
            }

            // Check if the account is locked
            if (AccountLockouts.ContainsKey(user.Email) && AccountLockouts[user.Email] > DateTime.Now)
            {
                // Account is locked
                ModelState.AddModelError("", "Your account is locked out. Please try again in 15 minutes.");
                return View(model);
            }

            var result = await _signInManager.PasswordSignInAsync(user.Email, model.Password, model.RememberMe, true);
            if (result.Succeeded)
            {
                // Reset failed login attempts after a successful login
                FailedLoginAttempts[user.Email] = 0;
                SetSession(user);
                return RedirectToAction("Index", "Home");
            }

            // Increment failed login attempts
            if (FailedLoginAttempts.ContainsKey(user.Email))
            {
                FailedLoginAttempts[user.Email]++;
            }
            else
            {
                FailedLoginAttempts[user.Email] = 1;
            }

            // Lock account after 3 failed login attempts
            if (FailedLoginAttempts[user.Email] >= 3)
            {
                AccountLockouts[user.Email] = DateTime.Now.AddMinutes(5); // Lock for 15 minutes
                ModelState.AddModelError("", "Your account is locked out. Please try again in 5 minutes.");
            }
            else
            {
                ModelState.AddModelError("", "Either your password or email is invalid. Please try again.");
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var userId = _userManager.GetUserId(User);
            if (userId != null)
            {
                await _auditLogService.LogActivity(userId, "User logged out.");
            }

            await _signInManager.SignOutAsync();
            HttpContext.Session.Clear();
            Response.Cookies.Delete(".AspNetCore.Identity.Application");

            return RedirectToAction("Login", "Account");
        }

        [HttpGet]
        public IActionResult ChangePassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            // Get the current time and compare it with the password change timestamp
            var currentTime = DateTime.UtcNow;

            // Minimum password change time check (e.g., 1 minute)
            var minPasswordAge = TimeSpan.FromMinutes(1);
            if (user.PasswordChangedAt.HasValue && currentTime - user.PasswordChangedAt.Value < minPasswordAge)
            {
                ModelState.AddModelError("", $"You cannot change your password within {minPasswordAge.TotalMinutes} minute of the last change.");
                return View(model);
            }

            // Maximum password age check (e.g., 30 days)
            var maxPasswordAge = TimeSpan.FromDays(30);
            if (user.PasswordChangedAt.HasValue && currentTime - user.PasswordChangedAt.Value > maxPasswordAge)
            {
                ModelState.AddModelError("", $"Your password is too old. Please change it.");
                return View(model);
            }

            // Check password history 
            var passwordHasher = new PasswordHasher<User>();
            foreach (var oldPassword in user.PreviousPasswords)
            {
                if (passwordHasher.VerifyHashedPassword(user, oldPassword.HashedPassword, model.NewPassword) == PasswordVerificationResult.Success)
                {
                    TempData["ErrorMessage"] = "You cannot reuse your previous passwords.";
                    return RedirectToAction("ChangePassword");
                }
            }

            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError("", error.Description);

                return View(model);
            }

            // Store the new password in history
            user.PreviousPasswords.Add(new PreviousPassword
            {
                HashedPassword = passwordHasher.HashPassword(user, model.NewPassword),
                DateChanged = DateTime.UtcNow,
                UserId = user.Id
            });

            // Keep only the last 2 passwords
            if (user.PreviousPasswords.Count > 2)
            {
                var oldestPassword = user.PreviousPasswords.OrderBy(p => p.DateChanged).First();
                user.PreviousPasswords.Remove(oldestPassword);
            }

            // Update the password change timestamp
            user.PasswordChangedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();

            await _signInManager.RefreshSignInAsync(user);
            TempData["SuccessMessage"] = "Password changed successfully!";
            return RedirectToAction("Index", "Home");
        }




        private void SetSession(User user)
        {
            HttpContext.Session.SetString("UserId", user.Id);
            HttpContext.Session.SetString("UserEmail", user.Email);
            HttpContext.Session.SetString("EncryptedNRIC", user.EncryptedNRIC); // Store encrypted NRIC in session
            ActiveSessions[user.Id] = HttpContext.Session.Id;
            HttpContext.Session.SetString("LastActivity", DateTime.Now.ToString("o"));
        }


        private string Encrypt(string input)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes("1234567890123456");
                aes.IV = Encoding.UTF8.GetBytes("1234567890123456");
                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
                    return Convert.ToBase64String(encryptedBytes);
                }
            }
        }

        public IActionResult TestSession()
        {
            HttpContext.Session.SetString("Test", "Session Active");
            return Content("Session started. Wait 1 min and refresh.");
        }

        public IActionResult CheckSession()
        {
            var lastActivity = HttpContext.Session.GetString("LastActivity");
            if (string.IsNullOrEmpty(lastActivity))
            {
                // No activity stored, treat as logged out
                return RedirectToAction("Login", "Account");
            }

            var lastActivityDate = DateTime.Parse(lastActivity); // Parse stored time
            var timeElapsed = DateTime.Now - lastActivityDate;

            if (timeElapsed.TotalSeconds > 15) // Session timeout after 15 seconds of inactivity
            {
                // Session expired
                return RedirectToAction("Login", "Account");
            }

            // Update the last activity timestamp to extend session
            HttpContext.Session.SetString("LastActivity", DateTime.Now.ToString("o"));

            return Content("Session still active.");
        }
    }
}
