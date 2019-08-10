namespace Requirements.Helpers
{
    using Microsoft.AspNetCore.Identity;
    using Requirements.Data.Entities;
    using Requirements.Models;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public interface IUserManager
    {
        Task<User> FindByEmailAsync(string email);

        Task<IdentityResult> CreateAsync(User user, string password);

        Task<SignInResult> PasswordSignInAsync(LoginViewModel model);

        Task<User> GetTwoFactorAuthenticationUserAsync();

        Task<SignInResult> TwoFactorAuthenticatorSignInAsync(string authCode, bool isPersistence, bool client);

        Task<string> GetAuthenticatorKeyAsync(User user);

        Task<IdentityResult> ResetAuthenticatorKeyAsync(User user);

        Task<bool> VerifyTwoFactorAuthAsync(User user, string tokenProvider, string code);

        string GetTokenProvider();

        Task<IdentityResult> SetTwoFactorEnabledAsync(User user, bool enabled);

        Task RefreshSignInAsync(User user);

        Task<int> CountRecoveryCodes(User user);

        Task<SignInResult> TwoFactorRecoveryCodeSignInAsync(string recoveryCode);

        Task<IEnumerable<string>> GenerateNewTwoFactorRecoveryCodesAsync(User user, int countOfCodes);

        Task SignOutAsync();

        Task<IdentityResult> UpdateAsync(User user);

        Task<IdentityResult> ChangePasswordAsync(User user, string oldPassword, string newPassword);

        Task<SignInResult> CheckPasswordSignInAsync(User user, string password);

        Task<IdentityResult> AddToRoleAsync(User user, string roleName);

        Task<bool> IsInRoleAsync(User user, string roleName);

        Task<string> GenerateEmailConfirmationTokenAsync(User user);

        Task<IdentityResult> ConfirmEmailAsync(User user, string token);

        Task<User> FindByIdAsync(string userId);

        Task<string> GeneratePasswordResetTokenAsync(User user);

        Task<IdentityResult> ResetPasswordAsync(User user, string token, string password);

        Task<List<User>> GetUsersAsync();

        Task RemoveUserFromRoleAsync(User user, string roleName);

        Task DeleteAsync(User user);

        Task<IEnumerable<User>> GetAllUsers();

        Task<IList<string>> GetRolesAsync(User user);

        Task<IList<User>> GetUsersInRoleAsync(string roleName);
    }
}
