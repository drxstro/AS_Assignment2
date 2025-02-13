using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Asn2_AS.Models
{
    public class User : IdentityUser
    {
        [Required]
        public string? FirstName { get; set; }

        [Required]
        public string? LastName { get; set; }

        [Required]
        public string? Gender { get; set; }

        [Required]
        public string? EncryptedNRIC { get; set; } // Encrypted NRIC

        [Required, DataType(DataType.Date)]
        public DateTime DateOfBirth { get; set; }

        public string? ResumePath { get; set; }

        [Required, DataType(DataType.MultilineText)]
        public string? WhoAmI { get; set; }

        [NotMapped]
        public IFormFile? Resume { get; set; } // File upload

        public List<PreviousPassword> PreviousPasswords { get; set; } = new List<PreviousPassword>();
        public DateTime? PasswordChangedAt { get; set; }
    }
}
