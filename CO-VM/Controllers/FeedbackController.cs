using CO_VM.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace CO_VM.Controllers
{
    [Route("Vaccine/[controller]")]
    [ApiController]
    public class FeedbackController : ControllerBase
    {
        vaccineManagementContext vm = new vaccineManagementContext();
        [Route("Feedback")]
        [HttpGet]
        public IActionResult GetCompletedVaccines(int userId)
        {
            var completedVaccines = vm.Bookings
                .Where(b => b.UserId == userId && b.Status == "Completed")
                .Select(b => new
                {
                    b.VaccineId,
                    VaccineName = b.Vaccine.VaccineName
                })
                .Distinct()
                .ToList();

            return Ok(completedVaccines);
        }

        [HttpPost]
        public IActionResult PostFeedback([FromBody] VaccinationFeedback feedback)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            feedback.SubmittedAt = DateTime.Now;
            vm.Add(feedback);
            vm.SaveChanges();
            return Ok(new { message = "Feedback submitted successfully." });
        }
    }
}



   
