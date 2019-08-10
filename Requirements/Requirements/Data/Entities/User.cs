namespace Requirements.Data.Entities
{
    using Microsoft.AspNetCore.Identity;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public class User : IdentityUser
    {
        public override string Id { get => base.Id; set => base.Id = value; }

        [Display(Name = "Nombre")]
        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [MaxLength(100, ErrorMessage = "El campo {0} solo puede contener un máximo de {1} caracteres")]
        [MinLength(3, ErrorMessage = "El campo {0} solo puede contener un minimo de {1} caracteres")]
        public string FirstName { get; set; }

        [Display(Name = "Apellidos")]
        [Required(ErrorMessage = "El campo {0} no puede estar vacío")]
        [MaxLength(100, ErrorMessage = "El campo {0} solo puede contener un máximo de {1} caracteres")]
        [MinLength(3, ErrorMessage = "El campo {0} solo puede contener un minimo de {1} caracteres")]
        public string LastName { get; set; }

        [Display(Name = "Nombre completo")]
        public string FullName { get { return $"{FirstName} {LastName}"; } }

        [NotMapped]
        [Display(Name = "Roles")]
        public string UserRoles { get; set; }

        public virtual ICollection<IdentityUserRole<string>> Roles { get; set; }

        public virtual ICollection<IdentityUserClaim<string>> Claims { get; set; }
    }
}
