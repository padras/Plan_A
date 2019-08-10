using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Query;
using Requirements.Data;
using Requirements.Data.Entities;
using Requirements.Helpers;
using System.Linq;
using System.Threading.Tasks;

namespace Requirements.Controllers
{
    public class RequirementsController : Controller
    {
        private readonly DataContext context;
        private readonly IUserManager userManager;

        public RequirementsController(DataContext context, IUserManager userManager)
        {
            this.context = context;
            this.userManager = userManager;
        }

        // GET: Requirements
        public async Task<IActionResult> Index()
        {
            var currentUser = await userManager.FindByEmailAsync(User.Identity.Name);
            object dataContext = null;

            if (User.IsInRole("Cliente") && User.Identity.IsAuthenticated)
            {

                dataContext = await context.Requirements
                    .Include(r => r.Owner)
                    .Include(r => r.Project)
                    .Include(r => r.Status)
                    .Where(o => o.OwnerId == currentUser.Id)
                    .ToListAsync();
            }
            else
            {
                dataContext = await context.Requirements.Include(r => r.Owner).Include(r => r.Project).Include(r => r.Status).ToListAsync();
            }
            return View(dataContext);
        }

        // GET: Requirements/Details/5
        public async Task<IActionResult> Details(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var requirement = await context.Requirements
                .Include(r => r.Owner)
                .Include(r => r.Project)
                .Include(r => r.Status)
                .FirstOrDefaultAsync(m => m.Id == id);
            if (requirement == null)
            {
                return NotFound();
            }

            return View(requirement);
        }

        // GET: Requirements/Create
        public async Task<IActionResult> Create()
        {
            var currentUser = await userManager.FindByEmailAsync(User.Identity.Name);
            var clients = await userManager.GetUsersInRoleAsync("Cliente");
            if (User.IsInRole("Cliente") && User.Identity.IsAuthenticated)
            {
                ViewData["OwnerId"] = new SelectList(clients, "Id", "FullName");

                ViewData["ProjectId"] = new SelectList(context.Projects
                    .Include(o => o.Owner)
                    .Where(p => p.OwnerId == currentUser.Id), "Id", "Name", currentUser.Id);

                ViewData["StatusId"] = new SelectList(context.Statuses, "Id", "Name");

                return View();
            }
            else
            {
                ViewData["OwnerId"] = new SelectList(clients, "Id", "FullName");
                ViewData["ProjectId"] = new SelectList(context.Projects, "Id", "Name");
                ViewData["StatusId"] = new SelectList(context.Statuses, "Id", "Name");
                return View();
            }
        }

        // POST: Requirements/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Requirement requirement)
        {
            if (User.IsInRole("Cliente") && User.Identity.IsAuthenticated)
            {
                if (ModelState.IsValid)
                {
                    context.Add(requirement);
                    await context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }

                var currentUser = await userManager.FindByEmailAsync(User.Identity.Name);
                var clients = await userManager.GetUsersInRoleAsync("Cliente");

                ViewData["OwnerId"] = new SelectList(clients, "Id", "FullName", requirement.OwnerId);

                ViewData["ProjectId"] = new SelectList(context.Projects
                    .Include(o => o.Owner)
                    .Where(p => p.OwnerId == currentUser.Id), "Id", "Name", requirement.ProjectId);

                ViewData["StatusId"] = new SelectList(context.Statuses, "Id", "Name", requirement.StatusId);
                return View(requirement);
            }
            else
            {
                if (ModelState.IsValid)
                {
                    context.Add(requirement);
                    await context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }
                var clients = await userManager.GetUsersInRoleAsync("Cliente");
                ViewData["OwnerId"] = new SelectList(clients, "Id", "FullName", requirement.OwnerId);
                ViewData["ProjectId"] = new SelectList(context.Projects, "Id", "Name", requirement.ProjectId);
                ViewData["StatusId"] = new SelectList(context.Statuses, "Id", "Name", requirement.StatusId);
                return View(requirement);
            }
        }

        // GET: Requirements/Edit/5
        public async Task<IActionResult> Edit(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var requirement = await context.Requirements.FindAsync(id);
            if (requirement == null)
            {
                return NotFound();
            }
            var clients = await userManager.GetUsersInRoleAsync("Cliente");
            ViewData["OwnerId"] = new SelectList(clients, "Id", "FullName", requirement.OwnerId);
            ViewData["ProjectId"] = new SelectList(context.Projects, "Id", "Name", requirement.ProjectId);
            ViewData["StatusId"] = new SelectList(context.Statuses, "Id", "Name", requirement.StatusId);
            return View(requirement);
        }

        // POST: Requirements/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string id, Requirement requirement)
        {
            if (id != requirement.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    context.Update(requirement);
                    await context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!RequirementExists(requirement.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            var clients = await userManager.GetUsersInRoleAsync("Cliente");
            ViewData["OwnerId"] = new SelectList(clients, "Id", "FullName", requirement.OwnerId);
            ViewData["ProjectId"] = new SelectList(context.Projects, "Id", "Name", requirement.ProjectId);
            ViewData["StatusId"] = new SelectList(context.Statuses, "Id", "Name", requirement.StatusId);
            return View(requirement);
        }

        // GET: Requirements/Delete/5
        public async Task<IActionResult> Delete(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var requirement = await context.Requirements
                .Include(r => r.Owner)
                .Include(r => r.Project)
                .Include(r => r.Status)
                .FirstOrDefaultAsync(m => m.Id == id);
            if (requirement == null)
            {
                return NotFound();
            }

            return View(requirement);
        }

        // POST: Requirements/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            var requirement = await context.Requirements.FindAsync(id);
            context.Requirements.Remove(requirement);
            await context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool RequirementExists(string id)
        {
            return context.Requirements.Any(e => e.Id == id);
        }
    }
}
