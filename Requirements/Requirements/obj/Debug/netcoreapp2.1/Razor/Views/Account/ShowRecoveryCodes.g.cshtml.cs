#pragma checksum "C:\Users\Andrey\Documents\GitHub\Plan_A\Requirements\Requirements\Views\Account\ShowRecoveryCodes.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "e25358ecb21dee79ed63766305f713f09b3fe008"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Account_ShowRecoveryCodes), @"mvc.1.0.view", @"/Views/Account/ShowRecoveryCodes.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Account/ShowRecoveryCodes.cshtml", typeof(AspNetCore.Views_Account_ShowRecoveryCodes))]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#line 1 "C:\Users\Andrey\Documents\GitHub\Plan_A\Requirements\Requirements\Views\_ViewImports.cshtml"
using Requirements;

#line default
#line hidden
#line 2 "C:\Users\Andrey\Documents\GitHub\Plan_A\Requirements\Requirements\Views\_ViewImports.cshtml"
using Requirements.Models;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"e25358ecb21dee79ed63766305f713f09b3fe008", @"/Views/Account/ShowRecoveryCodes.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"a58fab8bf32086f11cb28407d0495895cf1a826f", @"/Views/_ViewImports.cshtml")]
    public class Views_Account_ShowRecoveryCodes : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<ShowRecoveryCodesViewModel>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
#line 2 "C:\Users\Andrey\Documents\GitHub\Plan_A\Requirements\Requirements\Views\Account\ShowRecoveryCodes.cshtml"
  
    ViewData["Title"] = "Códigos de recuperación";

#line default
#line hidden
            BeginContext(94, 441, true);
            WriteLiteral(@"
    <h2>Códigos de recuperación</h2>
<div class=""alert alert-warning"" role=""alert"">
    <p>
        <span class=""glyphicon glyphicon-warning-sign""></span>
        <strong>
            Ponga estos códigos en un lugar seguro.
        </strong>
    </p>
    <p>
        Si pierde su dispositivo y no tiene los códigos de recuperación, perderá el acceso a su cuenta.
    </p>
</div>
<div class=""row"">
    <div class=""col-md-12"">
");
            EndContext();
#line 20 "C:\Users\Andrey\Documents\GitHub\Plan_A\Requirements\Requirements\Views\Account\ShowRecoveryCodes.cshtml"
         for (var row = 0; row < Model.RecoveryCodes.Length; row += 2)
        {

#line default
#line hidden
            BeginContext(618, 40, true);
            WriteLiteral("            <code class=\"recovery-code\">");
            EndContext();
            BeginContext(659, 24, false);
#line 22 "C:\Users\Andrey\Documents\GitHub\Plan_A\Requirements\Requirements\Views\Account\ShowRecoveryCodes.cshtml"
                                   Write(Model.RecoveryCodes[row]);

#line default
#line hidden
            EndContext();
            BeginContext(683, 7, true);
            WriteLiteral("</code>");
            EndContext();
            BeginContext(696, 6, true);
            WriteLiteral("&nbsp;");
            EndContext();
            BeginContext(709, 28, true);
            WriteLiteral("<code class=\"recovery-code\">");
            EndContext();
            BeginContext(738, 28, false);
#line 22 "C:\Users\Andrey\Documents\GitHub\Plan_A\Requirements\Requirements\Views\Account\ShowRecoveryCodes.cshtml"
                                                                                                                  Write(Model.RecoveryCodes[row + 1]);

#line default
#line hidden
            EndContext();
            BeginContext(766, 25, true);
            WriteLiteral("</code>\r\n        <br />\r\n");
            EndContext();
#line 24 "C:\Users\Andrey\Documents\GitHub\Plan_A\Requirements\Requirements\Views\Account\ShowRecoveryCodes.cshtml"
        }

#line default
#line hidden
            BeginContext(802, 18, true);
            WriteLiteral("    </div>\r\n</div>");
            EndContext();
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<ShowRecoveryCodesViewModel> Html { get; private set; }
    }
}
#pragma warning restore 1591
