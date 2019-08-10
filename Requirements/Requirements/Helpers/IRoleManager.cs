using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Rendering;
using Requirements.Data.Entities;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Requirements.Helpers
{
    public interface IRoleManager
    {
        Task<IdentityResult> CreateAsync(Role role);

        Task<IdentityResult> UpdateAsync(Role role);

        Task DeleteAsync(Role role);

        Task<Role> FindByIdAsync(string roleId);

        Task CheckRoleAsync(string roleName);

        Task<Role> FindByNameAsync(string roleName);

        Task<List<Role>> GetAllRolesAsync();

        SelectList GetRolesSelectList();
    }
}
