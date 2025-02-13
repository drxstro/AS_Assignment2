using System.ComponentModel.DataAnnotations;

namespace Asn2_AS.Models
{
    public class PreviousPassword
    {
        [Key]
        public int Id { get; set; }

        public string HashedPassword { get; set; }

        public DateTime DateChanged { get; set; }

        public string UserId { get; set; }

        public User User { get; set; }
    }
}
