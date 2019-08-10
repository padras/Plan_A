namespace Requirements.Models
{
    using Microsoft.AspNetCore.Mvc;

    public class ShowRecoveryCodesViewModel
    {
        [TempData]
        public string[] RecoveryCodes { get; set; }
    }
}
