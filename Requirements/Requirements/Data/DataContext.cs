namespace Requirements.Data
{
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore;
    using Requirements.Data.Entities;

    public class DataContext : IdentityDbContext<User, Role, string>
    {
        public DbSet<Status> Statuses { get; set; }
        public DbSet<Project> Projects { get; set; }
        public DbSet<Requirement> Requirements { get; set; }

        public DataContext(DbContextOptions<DataContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<User>().HasMany(u => u.Claims).WithOne().HasForeignKey(c => c.UserId).IsRequired().OnDelete(DeleteBehavior.Cascade);
            builder.Entity<User>().HasMany(u => u.Roles).WithOne().HasForeignKey(r => r.UserId).IsRequired().OnDelete(DeleteBehavior.Cascade);

            builder.Entity<Role>().HasMany(r => r.Claims).WithOne().HasForeignKey(c => c.RoleId).IsRequired().OnDelete(DeleteBehavior.Cascade);
            builder.Entity<Role>().HasMany(r => r.Users).WithOne().HasForeignKey(r => r.RoleId).IsRequired().OnDelete(DeleteBehavior.Cascade);

            builder.Entity<Status>().HasIndex(s => s.Name).IsUnique();

            builder.Entity<Project>().HasIndex(p => p.Name).IsUnique();

            builder.Entity<Project>().HasOne(s => s.Status).WithMany().HasForeignKey(s => s.StatusId).IsRequired(false).OnDelete(DeleteBehavior.SetNull);

            builder.Entity<Project>().HasOne(s => s.Owner).WithMany().HasForeignKey(s => s.OwnerId).IsRequired(false).OnDelete(DeleteBehavior.SetNull);

            builder.Entity<Requirement>().HasOne(s => s.Project).WithMany().HasForeignKey(s => s.ProjectId).IsRequired(false).OnDelete(DeleteBehavior.SetNull);

            builder.Entity<Requirement>().HasOne(s => s.Status).WithMany().HasForeignKey(s => s.StatusId).IsRequired(false).OnDelete(DeleteBehavior.SetNull);

            builder.Entity<Requirement>().HasOne(s => s.Owner).WithMany().HasForeignKey(s => s.OwnerId).IsRequired(false).OnDelete(DeleteBehavior.SetNull);
        }
    }
}
