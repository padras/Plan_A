using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Requirements.Data;
using Requirements.Data.Entities;
using System.Linq;
using System.Threading.Tasks;

namespace Requirements.Controllers
{
    public class StatusController : Controller
    {
        private readonly DataContext context;

        public StatusController(DataContext context)
        {
            this.context = context;
        }

        // GET: Status
        public async Task<IActionResult> Index()
        {
            return View(await context.Statuses.ToListAsync());
        }

        // GET: Status/Details/5
        public async Task<IActionResult> Details(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var status = await context.Statuses
                .FirstOrDefaultAsync(m => m.Id == id);
            if (status == null)
            {
                return NotFound();
            }

            return View(status);
        }

        // GET: Status/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Status/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Status model)
        {
            if (ModelState.IsValid)
            {
                var status = await context.Statuses.FindAsync(model.Name);
                if (status == null)
                {
                    context.Add(model);
                    await context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }
                ModelState.AddModelError(string.Empty, "Ya ha sido registrado un estado con este nombre");
            }
            return View(model);
        }

        // GET: Status/Edit/5
        public async Task<IActionResult> Edit(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var status = await context.Statuses.FindAsync(id);
            if (status == null)
            {
                return NotFound();
            }
            return View(status);
        }

        // POST: Status/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string id, Status status)
        {
            if (id != status.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    context.Update(status);
                    await context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!StatusExists(status.Id))
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
            return View(status);
        }

        // GET: Status/Delete/5
        public async Task<IActionResult> Delete(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var status = await context.Statuses
                .FirstOrDefaultAsync(m => m.Id == id);
            if (status == null)
            {
                return NotFound();
            }

            return View(status);
        }

        // POST: Status/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            var status = await context.Statuses.FindAsync(id);
            context.Statuses.Remove(status);
            await context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool StatusExists(string id)
        {
            return context.Statuses.Any(e => e.Id == id);
        }
    }
}
