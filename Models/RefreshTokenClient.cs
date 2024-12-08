using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace Zauth_net.Models
{
    public class RefreshTokenClient
    {
        [Key]
        public Guid RefreshTokenClientId { get; set; }
        public string Token { get; set; }
        public DateTime ExpiresAt { get; set; }
        public string CreatedByIp { get; set; }
        [Required]
        [ForeignKey("Client")]
        public Guid ClientId { get; set; }
        public Client Client { get; set; }
    }
}