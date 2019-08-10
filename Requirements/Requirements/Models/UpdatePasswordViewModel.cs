namespace Requirements.Models
{
    using System.ComponentModel.DataAnnotations;

    public class UpdatePasswordViewModel
    {
        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [StringLength(11, ErrorMessage = "El campo {0} solo puede contener un máximo de {1} caracteres", MinimumLength = 11)]
        [Display(Name = "Contraseña actual")]
        public string OldPassword { get; set; }

        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [StringLength(11, ErrorMessage = "El campo {0} solo puede contener un máximo de {1} caracteres", MinimumLength = 11)]
        [Display(Name = "Nueva contraseña")]
        public string NewPassword { get; set; }

        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [StringLength(11, ErrorMessage = "El campo {0} solo puede contener un máximo de {1} caracteres", MinimumLength = 11)]
        [Compare("NewPassword")]
        [Display(Name = "Confirmar contraseña")]
        public string Confirm { get; set; }
    }

}
