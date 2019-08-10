namespace Requirements.Models
{
    using System.ComponentModel.DataAnnotations;

    public class Activate2faViewModel
    {
        [Required]
        [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [RegularExpression(@"^[0-9]*$", ErrorMessage = "Debe ingresar solo números")]
        [Display(Name = "Código de verificación")]
        public string Code { get; set; }

        public string SharedKey { get; set; }

        public string AuthenticatorUri { get; set; }
    }
}
