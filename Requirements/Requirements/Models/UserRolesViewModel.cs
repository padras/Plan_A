using System.ComponentModel.DataAnnotations;

namespace Requirements.Models
{
    public class UserRolesViewModel
    {
        public string Id { get; set; }

        [Required(ErrorMessage = "El campo {0} es requerido")]
        [Display(Name = "Añadir rol")]
        public string RoleName { get; set; }
    }
}
