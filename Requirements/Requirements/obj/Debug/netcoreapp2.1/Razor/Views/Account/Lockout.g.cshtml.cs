#pragma checksum "C:\Users\dacam\OneDrive\Universidad\Teoría de Sistemas\Proyecto\el casi listo\Requirements (1)\Requirements\Requirements\Views\Account\Lockout.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "57f828c7742748fe2eae90bcefbce3097afaa412"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Account_Lockout), @"mvc.1.0.view", @"/Views/Account/Lockout.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Account/Lockout.cshtml", typeof(AspNetCore.Views_Account_Lockout))]
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
#line 1 "C:\Users\dacam\OneDrive\Universidad\Teoría de Sistemas\Proyecto\el casi listo\Requirements (1)\Requirements\Requirements\Views\_ViewImports.cshtml"
using Requirements;

#line default
#line hidden
#line 2 "C:\Users\dacam\OneDrive\Universidad\Teoría de Sistemas\Proyecto\el casi listo\Requirements (1)\Requirements\Requirements\Views\_ViewImports.cshtml"
using Requirements.Models;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"57f828c7742748fe2eae90bcefbce3097afaa412", @"/Views/Account/Lockout.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"a58fab8bf32086f11cb28407d0495895cf1a826f", @"/Views/_ViewImports.cshtml")]
    public class Views_Account_Lockout : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<dynamic>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
#line 1 "C:\Users\dacam\OneDrive\Universidad\Teoría de Sistemas\Proyecto\el casi listo\Requirements (1)\Requirements\Requirements\Views\Account\Lockout.cshtml"
  
    ViewData["Title"] = "Bloqueo de cuenta activo";

#line default
#line hidden
            BeginContext(60, 40, true);
            WriteLiteral("\r\n<header>\r\n    <h1 class=\"text-danger\">");
            EndContext();
            BeginContext(101, 17, false);
#line 6 "C:\Users\dacam\OneDrive\Universidad\Teoría de Sistemas\Proyecto\el casi listo\Requirements (1)\Requirements\Requirements\Views\Account\Lockout.cshtml"
                       Write(ViewData["Title"]);

#line default
#line hidden
            EndContext();
            BeginContext(118, 108, true);
            WriteLiteral("</h1>\r\n    <p class=\"text-danger\">\r\n        La cuenta ha sido bloqueada por 45 minutos.\r\n    </p>\r\n</header>");
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<dynamic> Html { get; private set; }
    }
}
#pragma warning restore 1591