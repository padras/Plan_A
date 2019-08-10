using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Requirements.Data.Entities;
using Requirements.Helpers;
using Requirements.Models;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Requirements.Controllers
{
    public class AccountController : Controller
    {
        private readonly IUserManager userHelper;
        private readonly IRoleManager roleManager;
        private readonly IConfiguration configuration;
        private readonly UrlEncoder urlEncoder;
        private readonly IEmailManager emailManager;
        private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
        private const string RecoveryCodesKey = nameof(RecoveryCodesKey);

        public AccountController(IUserManager userHelper,
                                 IRoleManager roleManager,
                                 IConfiguration configuration,
                                 UrlEncoder urlEncoder,
                                 IEmailManager emailManager)
        {
            this.userHelper = userHelper;
            this.roleManager = roleManager;
            this.configuration = configuration;
            this.urlEncoder = urlEncoder;
            this.emailManager = emailManager;
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> UpdateUser()
        {
            var user = await userHelper.FindByEmailAsync(User.Identity.Name);
            var model = new UpdateUserViewModel();
            if (user != null)
            {
                model.FirstName = user.FirstName;
                model.LastName = user.LastName;
            }

            return View(model);
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Settings()
        {
            var user = await userHelper.FindByEmailAsync(User.Identity.Name);
            var model = new SettingsViewModel();
            if (user != null)
            {
                model.FirstName = user.FirstName;
                model.LastName = user.LastName;
                model.Email = user.Email;
                model.TwoFactorEnabled = user.TwoFactorEnabled;
            }

            return View(model);
        }

        [HttpGet]
        [Authorize]
        public IActionResult UpdatePassword()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Login()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Home");
            }

            return View();
        }

        [HttpGet]
        public IActionResult LoginWith2fa()
        {
            var user = userHelper.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
            {
                throw new InvalidOperationException($"Unable to load two-factor authentication user.");
            }

            return View();
        }

        [HttpGet]
        public async Task<IActionResult> LoginWithRecoveryCode()
        {
            var user = await userHelper.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load two-factor authentication user.");
            }
            return View();
        }

        [HttpGet]
        [Authorize]
        public IActionResult Restart2fa()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Logout()
        {
            await userHelper.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Activate2fa()
        {
            var user = await userHelper.FindByEmailAsync(User.Identity.Name);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{ user.Id }'.");
            }

            var vm = new Activate2faViewModel();

            await LoadSharedKeyAndQrCodeUriAsync(user, vm);

            return View(vm);
        }

        [HttpGet]
        [Authorize]
        public IActionResult ShowRecoveryCodes()
        {
            var recoveryCodes = (string[])TempData[RecoveryCodesKey];
            if (recoveryCodes == null)
            {
                return RedirectToAction(nameof(Settings));
            }
            var model = new ShowRecoveryCodesViewModel { RecoveryCodes = recoveryCodes };
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> GenerateRecoveryWarning()
        {
            var user = await userHelper.FindByEmailAsync(User.Identity.Name);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{ user.Id }'.");
            }

            if (!user.TwoFactorEnabled)
            {
                throw new ApplicationException($"Cannot generate recovery codes for user with ID '{user.Id}' because they do not have 2FA enabled.");
            }

            return View("GenerateRecoveryCodesWarning");
        }

        [HttpGet]
        [Authorize(Roles = "Administrador")]
        public IActionResult Register()
        {
            ViewBag.Roles = roleManager.GetRolesSelectList();
            return View();
        }

        [HttpGet]
        public IActionResult RegisterCostumer()
        {
            return View();
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Lockout()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                return NotFound();
            }

            var user = await userHelper.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            var result = await userHelper.ConfirmEmailAsync(user, token);
            if (!result.Succeeded)
            {
                return NotFound();
            }

            return View();
        }

        [HttpGet]
        public IActionResult RecoveryPassword()
        {
            return View();
        }

        [HttpGet]
        public IActionResult RestartPassword(string token)
        {
            var vm = new RestartPasswordViewModel { Token = token };
            return View(vm);
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> UpdateUser(UpdateUserViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userHelper.FindByEmailAsync(User.Identity.Name);
                if (user != null)
                {
                    user.FirstName = model.FirstName;
                    user.LastName = model.LastName;
                    var respose = await userHelper.UpdateAsync(user);
                    if (respose.Succeeded)
                    {
                        ViewBag.UserMessage = "Se ha actualizado la información correctamente";
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, respose.Errors.FirstOrDefault().Description);
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Usuario no encontrado");
                }
            }

            return View(model);
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> UpdatePassword(UpdatePasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userHelper.FindByEmailAsync(User.Identity.Name);
                if (user != null)
                {
                    var result = await userHelper.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
                    if (result.Succeeded)
                    {
                        return RedirectToAction(nameof(Settings));
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, result.Errors.FirstOrDefault().Description);
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Usuario no encontrado");
                }
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await userHelper.PasswordSignInAsync(model);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }

                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(LoginWith2fa));
                }

                if (result.IsLockedOut)
                {
                    return RedirectToAction(nameof(Lockout));
                }
            }

            ModelState.AddModelError(string.Empty, "Hubo un error al iniciar sesión. Verifique los datos e intente nuevamente");
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userHelper.GetTwoFactorAuthenticationUserAsync();

                if (user == null)
                {
                    throw new InvalidOperationException($"Unable to load two-factor authentication user.");
                }

                var authCode = model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);
                var result = await userHelper.TwoFactorAuthenticatorSignInAsync(authCode, isPersistence: true, model.RememberDevice);

                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else if (result.IsLockedOut)
                {
                    return RedirectToAction(nameof(Lockout));
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Código de autentificador no permitido.");
                    return View();
                }
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWithRecoveryCode(LoginWithRecoveryCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await userHelper.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load two-factor authentication user.");
            }

            var recoveryCode = model.RecoveryCode.Replace(" ", string.Empty);

            var result = await userHelper.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

            if (result.Succeeded)
            {
                return RedirectToAction("Index", "Home");
            }
            if (result.IsLockedOut)
            {
                return RedirectToAction(nameof(Lockout));
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Código de recuperación no permitida");
                return View();
            }
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> PostRestart2fa()
        {
            var user = await userHelper.FindByEmailAsync(User.Identity.Name);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{ user.Id }'.");
            }

            await userHelper.SetTwoFactorEnabledAsync(user, false);
            await userHelper.ResetAuthenticatorKeyAsync(user);

            await userHelper.RefreshSignInAsync(user);

            return RedirectToAction(nameof(Activate2fa));
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Activate2fa(Activate2faViewModel model)
        {
            var user = await userHelper.FindByEmailAsync(User.Identity.Name);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{ user.Id }'.");
            }

            if (ModelState.IsValid)
            {
                var verificationCode = model.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

                var is2faTokenValid = await userHelper.VerifyTwoFactorAuthAsync(user, tokenProvider: userHelper.GetTokenProvider(), verificationCode);

                if (!is2faTokenValid)
                {
                    ModelState.AddModelError(string.Empty, "La clave de verificación no es válida");
                    await LoadSharedKeyAndQrCodeUriAsync(user, model);
                    return View();
                }
                await userHelper.SetTwoFactorEnabledAsync(user, true);

                if (await userHelper.CountRecoveryCodes(user) >= 0)
                {
                    var recoveryCodes = await userHelper.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                    TempData[RecoveryCodesKey] = recoveryCodes.ToArray();
                    return RedirectToAction(nameof(ShowRecoveryCodes));
                }
                else
                {
                    return RedirectToAction(nameof(Settings));
                }
            }
            await LoadSharedKeyAndQrCodeUriAsync(user, model);
            return View();
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Deactivate2fa()
        {
            var user = await userHelper.FindByEmailAsync(User.Identity.Name);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{ user.Id }'.");
            }

            var isUserLoggedIn = userHelper.GetTwoFactorAuthenticationUserAsync();

            if (isUserLoggedIn == null)
            {
                throw new InvalidOperationException($"Unable to load two-factor authentication user.");
            }

            var disable2faResult = await userHelper.SetTwoFactorEnabledAsync(user, false);
            if (!disable2faResult.Succeeded)
            {
                throw new InvalidOperationException($"Unexpected error occurred disabling 2FA for user with ID '{ user.Id }'.");
            }

            return RedirectToAction(nameof(Settings));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> GenerateRecoveryCodes()
        {
            var user = await userHelper.FindByEmailAsync(User.Identity.Name);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{ user.Id }'.");
            }

            if (!user.TwoFactorEnabled)
            {
                throw new ApplicationException($"Cannot generate recovery codes for user with ID '{user.Id}' as they do not have 2FA enabled.");
            }

            var recoveryCodes = await userHelper.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

            var model = new ShowRecoveryCodesViewModel { RecoveryCodes = recoveryCodes.ToArray() };

            return View(nameof(ShowRecoveryCodes), model);
        }

        [HttpPost]
        public async Task<IActionResult> CreateToken([FromBody] LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userHelper.FindByEmailAsync(model.Username);
                if (user != null)
                {
                    var result = await userHelper.CheckPasswordSignInAsync(
                        user,
                        model.Password);

                    if (result.Succeeded)
                    {
                        var claims = new[]
                        {
                            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                        };

                        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Tokens:Key"]));
                        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                        var token = new JwtSecurityToken(
                            configuration["Tokens:Issuer"],
                            configuration["Tokens:Audience"],
                            claims,
                            expires: DateTime.UtcNow.AddDays(15),
                            signingCredentials: credentials);

                        var results = new
                        {
                            token = new JwtSecurityTokenHandler().WriteToken(token),
                            expiration = token.ValidTo
                        };

                        return Created(string.Empty, results);
                    }
                }
            }

            return BadRequest();
        }

        [HttpPost]
        [Authorize(Roles = "Administrador")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterNewUserViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userHelper.FindByEmailAsync(model.Username);
                if (user == null)
                {
                    user = new User
                    {
                        FirstName = model.FirstName,
                        LastName = model.LastName,
                        Email = model.Username,
                        UserName = model.Username,
                    };

                    var result = await userHelper.CreateAsync(user, model.Password);
                    if (result != IdentityResult.Success)
                    {
                        ModelState.AddModelError(string.Empty, "La cuenta no pudo crearse correctamente");
                        return View(model);
                    }

                    await userHelper.AddToRoleAsync(user, model.UserRoles);

                    ViewBag.Message = "La cuenta ha sido creada correctamente. Debe habilitarla para iniciar sesión.";

                    return RedirectToAction("Index", "Users");
                }
                ModelState.AddModelError(string.Empty, "El correo electrónico ya ha sido asociado");
                ViewBag.Name = roleManager.GetRolesSelectList();
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RegisterCostumer(RegisterCostumerViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userHelper.FindByEmailAsync(model.Username);
                if (user == null)
                {
                    user = new User
                    {
                        FirstName = model.FirstName,
                        LastName = model.LastName,
                        Email = model.Username,
                        UserName = model.Username,
                    };

                    var result = await userHelper.CreateAsync(user, model.Password);
                    if (result != IdentityResult.Success)
                    {
                        ModelState.AddModelError(string.Empty, "La cuenta no pudo crearse correctamente");
                        return View(model);
                    }

                    await userHelper.AddToRoleAsync(user, "Cliente");

                    ViewBag.Message = "La cuenta ha sido creada correctamente. Debe esperar unos minutos hasta que su cuenta sea habilitada.";

                    return RedirectToAction("Index", "Home");
                }
                ModelState.AddModelError(string.Empty, "El correo electrónico ya ha sido asociado");
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RecoveryPassword(RecoveryPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userHelper.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    ModelState.AddModelError(string.Empty, "El correo electrónico no corresponde con ningun usuario registrado");
                    return View(model);
                }

                var myToken = await userHelper.GeneratePasswordResetTokenAsync(user);

                var link = Url.Action("RestartPassword", "Account", new { token = myToken }, protocol: HttpContext.Request.Scheme);

                emailManager.SendMail(model.Email, "Reinicio de contraseña", $"<h1>Reinicio de contraseña</h1>" +
                    $"Para reiniciar la contraseña haga clic en el siguiente enlace: </br></br><a href = \"{link}\">Reiniciar contraseña</a>");
                ViewBag.Message = "Las instrucciones para recuperar la contraseña han sido enviados al correo electrónico asociado";

                return View();
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RestartPassword(RestartPasswordViewModel model)
        {
            var user = await userHelper.FindByEmailAsync(model.Email);
            if (user != null)
            {
                var result = await userHelper.ResetPasswordAsync(user, model.Token, model.Password);
                if (result.Succeeded)
                {
                    ViewBag.Message = "La contraseña se ha reiniciado con exito";
                    return View();
                }

                ViewBag.Message = "Hubo un error al reiniciar la contraseña";
                return View(model);
            }

            ViewBag.Message = "Usuario no encontrado";
            return View(model);
        }

        [Authorize(Roles = "Administrador")]
        public async Task<IActionResult> ActivateAccount(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            var user = await userHelper.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            user.EmailConfirmed = true;

            await userHelper.UpdateAsync(user);

            return RedirectToAction("Index", "Users");
        }

        [Authorize(Roles = "Administrador")]
        public async Task<IActionResult> DeactivateAccount(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            var user = await userHelper.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            user.EmailConfirmed = false;

            await userHelper.UpdateAsync(user);

            return RedirectToAction("Index", "Users");
        }

        private async Task LoadSharedKeyAndQrCodeUriAsync(User user, Activate2faViewModel model)
        {
            var unformattedKey = await userHelper.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await userHelper.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await userHelper.GetAuthenticatorKeyAsync(user);
            }

            model.SharedKey = FormatKey(unformattedKey);

            model.AuthenticatorUri = GenerateQrCodeUri(user.Email, unformattedKey);
        }

        private string FormatKey(string unformattedKey)
        {
            var result = new StringBuilder();
            int currentPosition = 0;
            while (currentPosition + 4 < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition, 4)).Append(" ");
                currentPosition += 4;
            }
            if (currentPosition < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition));
            }

            return result.ToString().ToLowerInvariant();
        }

        private string GenerateQrCodeUri(string email, string unformattedKey)
        {
            return string.Format(
                AuthenticatorUriFormat,
                urlEncoder.Encode("Requirements"),
                urlEncoder.Encode(email),
                unformattedKey);
        }
    }
}