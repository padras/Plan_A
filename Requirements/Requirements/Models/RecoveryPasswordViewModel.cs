namespace Requirements.Models
{
    using System.ComponentModel.DataAnnotations;

    public class RecoveryPasswordViewModel
    {
        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [EmailAddress(ErrorMessage = "El campo {0} debe contener un email válido para su correcto funcionamiento")]
        [Display(Name = "Correo electrónico")]
        public string Email { get; set; }
    }
}
