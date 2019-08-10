using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Requirements.Data;
using Requirements.Data.Entities;
using Requirements.Helpers;
using System.Linq;
using System.Threading.Tasks;

namespace Requirements.Controllers
{
    [Authorize(Roles = "Administrador, Analista")]
    public class ProjectsController : Controller
    {
        private readonly DataContext context;
        private readonly IUserManager userManager;

        public ProjectsController(DataContext context, IUserManager userManager)
        {
            this.context = context;
            this.userManager = userManager;
        }

        // GET: Projects
        public async Task<IActionResult> Index()
        {
            var dataContext = context.Projects.Include(p => p.Owner).Include(p => p.Status);
            return View(await dataContext.ToListAsync());
        }

        // GET: Projects/Details/5
        public async Task<IActionResult> Details(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var project = await context.Projects
                .Include(p => p.Owner)
                .Include(p => p.Status)
                .FirstOrDefaultAsync(m => m.Id == id);
            if (project == null)
            {
                return NotFound();
            }

            return View(project);
        }

        // GET: Projects/Create
        public async Task<IActionResult> Create()
        {
            var clients = await userManager.GetUsersInRoleAsync("Cliente");
            ViewData["OwnerId"] = new SelectList(clients, "Id", "FullName");
            ViewData["StatusId"] = new SelectList(context.Statuses, "Id", "Name");
            return View();
        }

        // POST: Projects/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Project model)
        {
            if (ModelState.IsValid)
            {
                var project = await context.Projects.FindAsync(model.Name);
                if (project == null)
                {
                    context.Add(model);
                    await context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }
                ModelState.AddModelError(string.Empty, "Ya ha sido registrado un proyecto con este nombre");
            }

            var clients = await userManager.GetUsersInRoleAsync("Cliente");
            ViewData["OwnerId"] = new SelectList(clients, "Id", "FullName", model.OwnerId);
            ViewData["StatusId"] = new SelectList(context.Statuses, "Id", "Name", model.StatusId);
            return View(model);
        }

        // GET: Projects/Edit/5
        public async Task<IActionResult> Edit(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var project = await context.Projects.FindAsync(id);
            if (project == null)
            {
                return NotFound();
            }
            var clients = await userManager.GetUsersInRoleAsync("Cliente");
            ViewData["OwnerId"] = new SelectList(clients, "Id", "FullName", project.OwnerId);
            ViewData["StatusId"] = new SelectList(context.Statuses, "Id", "Name", project.StatusId);
            return View(project);
        }

        // POST: Projects/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string id, Project project)
        {
            if (id != project.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    context.Update(project);
                    await context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!ProjectExists(project.Id))
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
            ViewData["OwnerId"] = new SelectList(clients, "Id", "FullName", project.OwnerId);
            ViewData["StatusId"] = new SelectList(context.Statuses, "Id", "Name", project.StatusId);
            return View(project);
        }

        // GET: Projects/Delete/5
        public async Task<IActionResult> Delete(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var project = await context.Projects
                .Include(p => p.Owner)
                .Include(p => p.Status)
                .FirstOrDefaultAsync(m => m.Id == id);
            if (project == null)
            {
                return NotFound();
            }

            return View(project);
        }

        // POST: Projects/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            var project = await context.Projects.FindAsync(id);
            try
            {
                context.Projects.Remove(project);
                await context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!ProjectExists(project.Id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

        }

        private bool ProjectExists(string id)
        {
            return context.Projects.Any(e => e.Id == id);
        }
    }
}
