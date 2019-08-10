namespace Requirements.Data.Entities
{
    using Microsoft.AspNetCore.Identity;
    using System.Collections.Generic;

    public class Role : IdentityRole
    {
        public override string Id { get => base.Id; set => base.Id = value; }

        public override string Name { get => base.Name; set => base.Name = value; }

        public virtual ICollection<IdentityUserRole<string>> Users { get; set; }

        public virtual ICollection<IdentityRoleClaim<string>> Claims { get; set; }
    }
}
