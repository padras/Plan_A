namespace Requirements.Models
{
    using System.ComponentModel.DataAnnotations;

    public class UpdateUserViewModel
    {
        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [RegularExpression(@"^[A-Za-zéÉñÑ ]*$", ErrorMessage = "Debe ingresar solo letras")]
        [Display(Name = "Nombre")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [Display(Name = "Apellidos")]
        [RegularExpression(@"^[A-Za-zéÉñÑ ]*$", ErrorMessage = "Debe ingresar solo letras")]
        public string LastName { get; set; }
    }
}
