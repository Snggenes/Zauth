using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Zauth_net.Models;

namespace Zauth_net.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        public DbSet<Client> Clients { get; set; }
        public DbSet<RefreshTokenClient> RefreshTokenClients { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<Client>()
                .HasIndex(c => c.Email)
                .IsUnique();

            modelBuilder.Entity<RefreshTokenClient>()
                .HasIndex(c => c.Token)
                .IsUnique();

            modelBuilder.Entity<RefreshTokenClient>()
                .HasIndex(c => c.ClientId);

        }
    }
}