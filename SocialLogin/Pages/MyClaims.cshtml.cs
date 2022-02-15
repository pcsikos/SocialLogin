using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SocialLogin.Pages
{
    public class MyClaimsModel : PageModel
    {
        public IDictionary<string, string?> AuthProperties { get; set; }

        public async void OnGetAsync()
        {
            var authResult = await HttpContext.AuthenticateAsync();
            AuthProperties = authResult.Properties == null ? new Dictionary<string, string?>() : authResult.Properties.Items;
        }
    }
}
