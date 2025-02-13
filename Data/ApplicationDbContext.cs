using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Asn2_AS.Models;

namespace Asn2_AS.Data
{
    public class ApplicationDbContext : IdentityDbContext<User> // Inherit IdentityDbContext with User
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<AuditLog> AuditLogs { get; set; }
        // No need to define a DbSet<User> here; it's handled by IdentityDbContext

        public DbSet<PreviousPassword> PreviousPasswords { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<PreviousPassword>()
           .HasOne(p => p.User)
           .WithMany(u => u.PreviousPasswords)
           .HasForeignKey(p => p.UserId)
           .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
