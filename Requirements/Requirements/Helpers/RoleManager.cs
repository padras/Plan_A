using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Requirements.Data.Entities;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Requirements.Helpers
{
    public class RoleManager : IRoleManager
    {
        private readonly RoleManager<Role> roleManager;

        public RoleManager(RoleManager<Role> roleManager)
        {
            this.roleManager = roleManager;
        }

        public async Task<IdentityResult> CreateAsync(Role role)
        {
            return await roleManager.CreateAsync(role);
        }

        public async Task DeleteAsync(Role role)
        {
            await roleManager.DeleteAsync(role);
        }

        public async Task<Role> FindByIdAsync(string roleId)
        {
            return await roleManager.FindByIdAsync(roleId);
        }

        public async Task<Role> FindByNameAsync(string roleName)
        {
            return await roleManager.FindByNameAsync(roleName);
        }

        public async Task<IdentityResult> UpdateAsync(Role role)
        {
            return await roleManager.UpdateAsync(role);
        }

        public SelectList GetRolesSelectList()
        {
            return new SelectList(roleManager.Roles.ToList(), "Name", "Name");
        }

        public async Task CheckRoleAsync(string roleName)
        {
            var roleExists = await roleManager.RoleExistsAsync(roleName);
            if (!roleExists)
            {
                await roleManager.CreateAsync(new Role
                {
                    Name = roleName
                });
            }
        }

        public async Task<List<Role>> GetAllRolesAsync()
        {
            return await roleManager.Roles
                .Select(r => new Role
                {
                    Id = r.Id,
                    Name = r.Name
                })
                .OrderBy(r => r.Name)
                .ToListAsync();
        }
    }
}
