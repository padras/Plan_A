namespace Requirements.Models
{
    using System.ComponentModel.DataAnnotations;

    public class SettingsViewModel
    {
        [Display(Name = "Nombre")]
        public string FirstName { get; set; }

        [Display(Name = "Apellidos")]
        public string LastName { get; set; }

        [Display(Name = "Nombre completo")]
        public string FullName { get { return $"{ FirstName } { LastName }"; } }

        [Display(Name = "Correo electrónico")]
        public string Email { get; set; }

        [Display(Name = "Autenticación de dos pasos")]
        public bool TwoFactorEnabled { get; set; }
    }
}
