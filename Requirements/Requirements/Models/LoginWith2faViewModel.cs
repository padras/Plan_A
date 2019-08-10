namespace Requirements.Models
{
    using System.ComponentModel.DataAnnotations;

    public class LoginWith2faViewModel
    {
        [Required]
        [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [RegularExpression(@"^[0-9]*$", ErrorMessage = "Debe ingresar solo números")]
        [Display(Name = "Código de autentificación")]
        public string TwoFactorCode { get; set; }

        [Display(Name = "Recordar dispositivo")]
        public bool RememberDevice { get; set; }
    }
}
