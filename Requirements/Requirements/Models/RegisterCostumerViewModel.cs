using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Requirements.Models
{
    public class RegisterCostumerViewModel
    {
        public string Id { get; set; }

        [Display(Name = "Nombre")]
        [RegularExpression(@"^[A-Za-záÁéÉíÍóÓúÚñÑ ]*$", ErrorMessage = "Debe ingresar solo letras")]
        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [StringLength(100, ErrorMessage = "El campo {0} solo puede contener un máximo de {1} y minimo {2} caracteres", MinimumLength = 3)]
        public string FirstName { get; set; }

        [Display(Name = "Apellidos")]
        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [RegularExpression(@"^[A-Za-záÁéÉíÍóÓúÚñÑ ]*$", ErrorMessage = "Debe ingresar solo letras")]
        [StringLength(100, ErrorMessage = "El campo {0} solo puede contener un máximo de {1} y minimo {2} caracteres", MinimumLength = 3)]
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
    }
}
