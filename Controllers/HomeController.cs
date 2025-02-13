using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Asn2_AS.Models;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Asn2_AS.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<User> _userManager;

        public HomeController(UserManager<User> userManager)
        {
            _userManager = userManager;
        }

        public async Task<IActionResult> Index()
        {
            // Get the current logged-in user's ID
            var userId = _userManager.GetUserId(User);
            if (userId == null)
            {
                return RedirectToAction("Login", "Account");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return RedirectToAction("Login", "Account");
            }

            // Return the user details to the homepage view
            return View(user);
        }
    }
}
