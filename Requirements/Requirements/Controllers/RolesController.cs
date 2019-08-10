namespace Requirements.Controllers
{
    using Requirements.Data.Entities;
    using Requirements.Helpers;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using System.Threading.Tasks;

    [Authorize(Roles = "Administrador")]
    public class RolesController : Controller
    {
        private readonly IRoleManager roleManager;

        public RolesController(IRoleManager roleManager)
        {
            this.roleManager = roleManager;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            return View(await roleManager.GetAllRolesAsync());
        }

        [HttpGet]
        public async Task<IActionResult> Details(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var role = await roleManager.FindByIdAsync(id);
            if (role == null)
            {
                return NotFound();
            }

            return View(role);
        }

        [HttpGet]
        public IActionResult Create()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Edit(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            var role = await roleManager.FindByIdAsync(id);
            
            if (role == null)
            {
                return NotFound();
            }

            var model = new Role
            {
                Name = role.Name
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Role model)
        {
            if (ModelState.IsValid)
            {
                var role = await roleManager.FindByNameAsync(model.Name);
                if (role == null)
                {
                    role = new Role
                    {
                        Id = model.Id,
                        Name = model.Name,
                    };

                    var result = await roleManager.CreateAsync(role);
                    if (result != IdentityResult.Success)
                    {
                        ModelState.AddModelError(string.Empty, "The role couldn't be created.");
                        return View(model);
                    }
                    return RedirectToAction(nameof(Index));
                }
                ModelState.AddModelError(string.Empty, "The role is already registered.");
            }

            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> Delete(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            var user = await roleManager.FindByIdAsync(id);
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

            var user = await roleManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            await roleManager.DeleteAsync(user);
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(Role model)
        {
            if (ModelState.IsValid)
            {
                var role = await roleManager.FindByIdAsync(model.Id);

                if (role != null)
                {
                    role.Name = model.Name;


                    var result = await roleManager.UpdateAsync(role);
                    if (result != IdentityResult.Success)
                    {
                        ModelState.AddModelError(string.Empty, "The role couldn't be updated.");
                        return View(model);
                    }
                    return RedirectToAction(nameof(Index));
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Role no found.");
                }

            }
            return View(model);
        }
    }
}
