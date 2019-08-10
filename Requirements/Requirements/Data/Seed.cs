namespace Requirements.Data
{
    using Microsoft.AspNetCore.Identity;
    using Requirements.Data.Entities;
    using Requirements.Helpers;
    using System;
    using System.Threading.Tasks;

    public class Seed
    {
        private readonly DataContext context;
        private readonly IUserManager userManager;
        private readonly IRoleManager roleManager;

        public Seed(DataContext context, IUserManager userManager, IRoleManager roleManager)
        {
            this.context = context;
            this.userManager = userManager;
            this.roleManager = roleManager;
        }

        public async Task SeedAsync()
        {
            await context.Database.EnsureCreatedAsync();

            await CheckRolesAsync();

            await CheckUserAsync(email: "requirementsProyect@gmail.com",
                                 firstName: "Daniela",
                                 lastName: "Campos Calderon",
                                 password: "ProyectoTeo",
                                 role: "Administrador");

            await CheckUserAsync(email: "aflores2989@gmail.com",
                                 firstName: "Andrea",
                                 lastName: "Flores Chaves",
                                 password: "ProyectoTeo",
                                 role: "Analista");

            await CheckUserAsync(email: "andreypadiasc@gmail.com",
                                 firstName: "Andrey",
                                 lastName: "Padías",
                                 password: "ProyectoTeo",
                                 role: "Cliente");
        }

        private async Task CheckRolesAsync()
        {
            await roleManager.CheckRoleAsync("Administrador");
            await roleManager.CheckRoleAsync("Analista");
            await roleManager.CheckRoleAsync("Cliente");
        }

        private async Task<User> CheckUserAsync(string email, string firstName, string lastName, string password, string role)
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = await AddUser(email, firstName, lastName, password, role);
            }

            var isInRole = await userManager.IsInRoleAsync(user, role);
            if (!isInRole)
            {
                await userManager.AddToRoleAsync(user, role);
            }

            return user;
        }

        private async Task<User> AddUser(string email, string firstName, string lastName, string password, string role)
        {
            var user = new User
            {
                FirstName = firstName,
                LastName = lastName,
                Email = email,
                UserName = email,
            };

            var result = await userManager.CreateAsync(user, password);
            if (result != IdentityResult.Success)
            {
                throw new InvalidOperationException("Could not create the user in seeder");
            }

            await userManager.AddToRoleAsync(user, role);
            var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
            await userManager.ConfirmEmailAsync(user, token);
            return user;
        }
    }
}
