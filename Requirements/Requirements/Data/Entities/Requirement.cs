using System;
using System.ComponentModel.DataAnnotations;

namespace Requirements.Data.Entities
{
    public class Requirement
    {
        public string Id { get; set; }

        [Display(Name = "Proyecto")]
        public string ProjectId { get; set; }

        [Display(Name = "Proyecto")]
        public virtual Project Project { get; set; }

        [Display(Name = "Nombre")]
        [Required(ErrorMessage = "El campo {0} es obligatorio")]
        [StringLength(maximumLength: 30, ErrorMessage = "El campo {0} no puede contener más de {1} y menos de {2} caracteres", MinimumLength = 8)]
        public string Name { get; set; }

        [Display(Name = "Descripción")]
        [Required(ErrorMessage = "El campo {0} es obligatorio")]
        [StringLength(255, ErrorMessage = "El campo {0} no puede contener más de {1} caracteres")]
        public string Description { get; set; }

        [Display(Name = "Estado")]
        public string StatusId { get; set; }

        [Display(Name = "Estado")]
        public virtual Status Status { get; set; }

        [Display(Name = "Propietario")]
        public string OwnerId { get; set; }

        [Display(Name = "Propietario")]
        public virtual User Owner { get; set; }

        [Display(Name = "Fecha de inicio")]
        [DataType(DataType.Date)]
        public DateTime StartDate { get; set; }

        [Display(Name = "Fecha de finalización")]
        [DataType(DataType.Date)]
        public DateTime? FinishDate { get; set; }
    }
}
