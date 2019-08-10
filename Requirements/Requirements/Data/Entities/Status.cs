using System.ComponentModel.DataAnnotations;

namespace Requirements.Data.Entities
{
    public class Status
    {
        public string Id { get; set; }

        [Display(Name = "Nombre")]
        [Required(ErrorMessage = "El campo {0} es obligatorio")]
        [StringLength(255, ErrorMessage = "El campo {0} no puede contener más de {1} caracteres")]
        public string Name { get; set; }

        [Display(Name = "Descripción")]
        [Required(ErrorMessage = "El campo {0} es obligatorio")]
        [StringLength(255, ErrorMessage = "El campo {0} no puede contener más de {1} caracteres")]
        public string Description { get; set; }
    }
}
