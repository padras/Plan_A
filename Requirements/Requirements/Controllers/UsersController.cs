namespace Requirements.Controllers
{
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Requirements.Helpers;
    using Requirements.Models;
    using System.Threading.Tasks;

    [Authorize(Roles = "Administrador")]
    public class UsersController : Controller
    {
        private readonly IUserManager userManager;
        private readonly IRoleManager roleManager;

        public UsersController(IUserManager userManager, IRoleManager roleManager)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            return View(await userManager.GetAllUsers());
        }

        [HttpGet]
        public async Task<IActionResult> Delete(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            var user = await userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }
            return View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            var user = await userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            await userManager.DeleteAsync(user);
            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> Edit(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            var user = await userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            var vm = new RegisterNewUserViewModel
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName
            };

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(RegisterNewUserViewModel vm)
        {
            if (!ModelState.IsValid)
            {
                var user = await userManager.FindByIdAsync(vm.Id);
                if (user != null)
                {
                    user.FirstName = vm.FirstName;
                    user.LastName = vm.LastName;

                    var result = await userManager.UpdateAsync(user);
                    if (!result.Succeeded)
                    {
                        ModelState.AddModelError(string.Empty, "La información de la cuenta no pudo modificarse correctamente");
                        return View(vm);
                    }

                    ViewBag.Message = "La información de la cuenta ha sido actualizada";
                    return View(vm);
                }
            }

            return View(vm);
        }
    }
}
