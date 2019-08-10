namespace Requirements.Helpers
{
    using Microsoft.AspNetCore.Identity;
    using Microsoft.EntityFrameworkCore;
    using Requirements.Data.Entities;
    using Requirements.Models;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    public class UserManager : IUserManager
    {
        private readonly UserManager<User> userManager;
        private readonly SignInManager<User> signInManager;
        private readonly RoleManager<Role> roleManager;

        public UserManager(UserManager<User> userManager, SignInManager<User> signInManager, RoleManager<Role> roleManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
        }

        public async Task<IdentityResult> CreateAsync(User user, string password)
        {
            return await userManager.CreateAsync(user, password);
        }

        public async Task<User> FindByEmailAsync(string email)
        {
            return await userManager.FindByEmailAsync(email);
        }

        public async Task<SignInResult> PasswordSignInAsync(LoginViewModel model)
        {
            return await signInManager.PasswordSignInAsync(
                model.Username,
                model.Password,
                model.RememberMe,
                true);
        }

        public async Task<User> GetTwoFactorAuthenticationUserAsync()
        {
            return await signInManager.GetTwoFactorAuthenticationUserAsync();
        }

        public async Task<SignInResult> TwoFactorAuthenticatorSignInAsync(string authCode, bool isPersistence, bool client)
        {
            return await signInManager.TwoFactorAuthenticatorSignInAsync(authCode, isPersistence, client);
        }

        public async Task<SignInResult> TwoFactorRecoveryCodeSignInAsync(string recoveryCode)
        {
            return await signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);
        }

        public async Task<string> GetAuthenticatorKeyAsync(User user)
        {
            return await userManager.GetAuthenticatorKeyAsync(user);
        }

        public async Task<IdentityResult> ResetAuthenticatorKeyAsync(User user)
        {
            return await userManager.ResetAuthenticatorKeyAsync(user);
        }

        public async Task<bool> VerifyTwoFactorAuthAsync(User user, string tokenProvider, string code)
        {
            return await userManager.VerifyTwoFactorTokenAsync(user, tokenProvider, code);
        }

        public string GetTokenProvider()
        {
            return userManager.Options.Tokens.AuthenticatorTokenProvider;
        }

        public async Task<IdentityResult> SetTwoFactorEnabledAsync(User user, bool enabled)
        {
            return await userManager.SetTwoFactorEnabledAsync(user, enabled);
        }

        public async Task RefreshSignInAsync(User user)
        {
            await signInManager.RefreshSignInAsync(user);
        }

        public async Task<int> CountRecoveryCodes(User user)
        {
            return await userManager.CountRecoveryCodesAsync(user);
        }

        public async Task<IEnumerable<string>> GenerateNewTwoFactorRecoveryCodesAsync(User user, int countOfCodes)
        {
            return await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, countOfCodes);
        }

        public async Task SignOutAsync()
        {
            await signInManager.SignOutAsync();
        }

        public async Task<IdentityResult> UpdateAsync(User user)
        {
            return await userManager.UpdateAsync(user);
        }

        public async Task<IdentityResult> ChangePasswordAsync(User user, string oldPassword, string newPassword)
        {
            return await userManager.ChangePasswordAsync(user, oldPassword, newPassword);
        }

        public async Task<SignInResult> CheckPasswordSignInAsync(User user, string password)
        {
            return await signInManager.CheckPasswordSignInAsync(
                user,
                password,
                false);
        }



        public async Task<IdentityResult> AddToRoleAsync(User user, string roleName)
        {
            return await userManager.AddToRoleAsync(user, roleName);
        }

        public async Task<bool> IsInRoleAsync(User user, string roleName)
        {
            return await userManager.IsInRoleAsync(user, roleName);
        }

        public async Task<IdentityResult> ConfirmEmailAsync(User user, string token)
        {
            return await userManager.ConfirmEmailAsync(user, token);
        }

        public async Task<string> GenerateEmailConfirmationTokenAsync(User user)
        {
            return await userManager.GenerateEmailConfirmationTokenAsync(user);
        }

        public async Task<User> FindByIdAsync(string userId)
        {
            return await userManager.FindByIdAsync(userId);
        }

        public async Task<string> GeneratePasswordResetTokenAsync(User user)
        {
            return await userManager.GeneratePasswordResetTokenAsync(user);
        }

        public async Task<IdentityResult> ResetPasswordAsync(User user, string token, string password)
        {
            return await userManager.ResetPasswordAsync(user, token, password);
        }

        public async Task<List<User>> GetUsersAsync()
        {
            return await userManager.Users
                .OrderBy(u => u.FirstName)
                .ThenBy(u => u.LastName)
                .ToListAsync();
        }

        public async Task RemoveUserFromRoleAsync(User user, string roleName)
        {
            await userManager.RemoveFromRoleAsync(user, roleName);
        }

        public async Task DeleteAsync(User user)
        {
            await userManager.DeleteAsync(user);
        }

        public async Task<IEnumerable<User>> GetAllUsers()
        {
            var userList = await (from user in userManager.Users
                                  select new
                                  {
                                      UserId = user.Id,
                                      Username = user.UserName,
                                      user.Email,
                                      user.EmailConfirmed,
                                      RoleNames = (from userRole in user.Roles
                                                   join role in roleManager.Roles
                                                   on userRole.RoleId
                                                   equals role.Id
                                                   select role.Name)
                                                  .FirstOrDefault()
                                  }).ToListAsync();

            var userListVm = userList.Select(p => new User
            {
                Id = p.UserId,
                UserName = p.Username,
                Email = p.Email,
                EmailConfirmed = p.EmailConfirmed,
                UserRoles = string.Join(", ", p.RoleNames)
            });

            return userListVm;
        }

        public async Task<IList<string>> GetRolesAsync(User user)
        {
            return await userManager.GetRolesAsync(user);
        }

        public async Task<IList<User>> GetUsersInRoleAsync(string roleName)
        {
            return await userManager.GetUsersInRoleAsync(roleName);
        }
    }
}