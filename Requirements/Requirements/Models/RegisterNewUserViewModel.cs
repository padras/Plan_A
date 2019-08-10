namespace Requirements.Models
{
    using System.ComponentModel.DataAnnotations;

    public class RegisterNewUserViewModel
    {
        public string Id { get; set; }

        [Display(Name = "Nombre")]
        [RegularExpression(@"^[A-Za-záÁéÉíÍóÓúÚñÑ ]*$", ErrorMessage = "Debe ingresar solo letras")]
        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [MaxLength(100, ErrorMessage = "El campo {0} solo puede contener un máximo de {1} caracteres")]
        [MinLength(2, ErrorMessage = "El campo {0} solo puede contener un minimo de {1} caracteres")]
        public string FirstName { get; set; }

        [Display(Name = "Apellidos")]
        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [RegularExpression(@"^[A-Za-záÁéÉíÍóÓúÚñÑ ]*$", ErrorMessage = "Debe ingresar solo letras")]
        [MaxLength(100, ErrorMessage = "El campo {0} solo puede contener un máximo de {1} caracteres")]
        [MinLength(2, ErrorMessage = "El campo {0} solo puede contener un minimo de {1} caracteres")]
        public string LastName { get; set; }

        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [DataType(DataType.EmailAddress)]
        [Display(Name = "Correo electrónico")]
        public string Username { get; set; }

        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [StringLength(11, ErrorMessage = "El campo {0} solo puede contener un unicamente {1} caracteres", MinimumLength = 11)]
        [Display(Name = "Contraseña")]
        public string Password { get; set; }

        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [StringLength(11, ErrorMessage = "El campo {0} solo puede contener un unicamente {1} caracteres", MinimumLength = 11)]
        [Compare("Password")]
        [Display(Name = "Confirmar contraseña")]
        public string Confirm { get; set; }

        [Required]
        [Display(Name = "Rol")]
        public string UserRoles { get; set; }
    }
}
