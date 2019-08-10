namespace Requirements.Models
{
    using System.ComponentModel.DataAnnotations;

    public class RestartPasswordViewModel
    {
        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [DataType(DataType.EmailAddress)]
        [Display(Name = "Correo electrónico")]
        public string Email { get; set; }

        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [MaxLength(11, ErrorMessage = "El campo {0} solo puede contener un máximo de {1} caracteres")]
        [MinLength(6, ErrorMessage = "El campo {0} solo puede contener un minimo de {1} caracteres")]
        [Display(Name = "Contraseña")]
        public string Password { get; set; }

        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [MaxLength(11, ErrorMessage = "El campo {0} solo puede contener un máximo de {1} caracteres")]
        [MinLength(6, ErrorMessage = "El campo {0} solo puede contener un minimo de {1} caracteres")]
        [Compare("Password")]
        [Display(Name = "Confirmar contraseña")]
        public string ConfirmPassword { get; set; }

        [Required]
        public string Token { get; set; }
    }
}
