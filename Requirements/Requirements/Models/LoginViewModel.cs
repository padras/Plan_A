namespace Requirements.Models
{
    using System.ComponentModel.DataAnnotations;

    public class LoginViewModel
    {
        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [EmailAddress(ErrorMessage = "El campo {0} no contiene un formato válido de correo electrónico")]
        [Display(Name = "Correo electrónico")]
        public string Username { get; set; }

        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [StringLength(11, ErrorMessage = "El campo {0} solo puede contener un máximo de {1} caracteres", MinimumLength = 11)]
        [Display(Name = "Contraseña")]
        public string Password { get; set; }

        [Display(Name = "Recordarme")]
        public bool RememberMe { get; set; }
    }
}
