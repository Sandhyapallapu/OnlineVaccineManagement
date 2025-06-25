using CO_VM.Models;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace CO_VM.Controllers
{
    public class VaccineController : Controller
    {
        vaccineManagementContext ob = new vaccineManagementContext();
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult UserDashboard()
        {
            try
            {
                int userId = Convert.ToInt32(HttpContext.Session.GetString("UserId"));

                var user = ob.Users.FirstOrDefault(u => u.UserId == userId);
                var family = ob.Families.Where(f => f.UserId == userId).ToList();
                var familyIds = family.Select(f => f.FamilyId).ToList();


                var bookings = ob.Bookings
                    .Where(b => b.UserId == userId || (b.FamilyId != null && familyIds.Contains(b.FamilyId.Value)))
                    .OrderByDescending(b => b.BookingDate)
                    .ToList();

                foreach (var booking in bookings)
                {
                    booking.Family = booking.Family ?? family.FirstOrDefault(f => f.FamilyId == booking.FamilyId);
                    booking.Vaccine = booking.Vaccine ?? ob.Vaccines.FirstOrDefault(v => v.VaccineId == booking.VaccineId);
                    booking.Slot = booking.Slot ?? ob.Slots.FirstOrDefault(s => s.SlotId == booking.SlotId);
                }

                ViewBag.User = user;
                ViewBag.Family = family;
                ViewBag.BookingCount = bookings.Count;
                ViewBag.Bookings = bookings;

                return View();

            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in UserDashboard.");
                return RedirectToAction("Error");

            }
        }

        [HttpPost]
        public IActionResult DeleteFamily(int id)
        {
            try
            {
                var family = ob.Families.FirstOrDefault(f => f.FamilyId == id);
                if (family != null)
                {
                    ob.Families.Remove(family);
                    ob.SaveChangesAsync();
                }

                return RedirectToAction("UserDashboard");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in Delete Family.");
                return RedirectToAction("Error");

            }

        }

        // Show the Add Family Member form
        [HttpGet]
        public IActionResult Family()
        {
            try
            {
                var model = new Family();
                ViewBag.Relations = ob.Relations.ToList();
                return View(model);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in Family.");
                return RedirectToAction("Error");

            }
        }
      
        [HttpPost]
        public IActionResult Family(Family model)
        {
            try
            {
                if (ModelState.IsValid)
                {

                    int userId = Convert.ToInt32(HttpContext.Session.GetString("UserId"));
                    model.UserId = userId;


                    ob.Families.Add(model);
                    ob.SaveChangesAsync();


                    return RedirectToAction("UserDashboard");
                }

                return View(model);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in Family.");
                return RedirectToAction("Error");

            }

        }

        [HttpGet]

        public IActionResult Vaccines()
        {
            try
            {
                if (HttpContext.Session.GetString("UserId") == null)
                {
                    return RedirectToAction("Login", "Vaccine");

                }
                // Cache control for security 

                Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";

                Response.Headers["Pragma"] = "no-cache";

                Response.Headers["Expires"] = "-1";
                var res = (from t in ob.Vaccines select t).ToList();

                return View(res);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in Family.");
                return RedirectToAction("Error");

            }

        }

        [HttpPost]
        public IActionResult Vaccines(string search, string state, string centre)
        {
            try
            {
                // Start with all vaccines and join to centres
                var vaccinesQuery = from v in ob.Vaccines
                                    join vc in ob.VaccineCentres on v.VaccineId equals vc.VaccineId
                                    join c in ob.Centres on vc.CentreId equals c.CentreId
                                    select new { Vaccine = v, Centre = c };

                var result = vaccinesQuery.Where(s => s.Vaccine.VaccineName.Contains(search) || s.Centre.State.Contains(search));


                return View(result.ToList());

                //bool hasSearch = !string.IsNullOrWhiteSpace(search);
                //bool hasState = !string.IsNullOrWhiteSpace(state);
                //bool hasCentre = !string.IsNullOrWhiteSpace(centre);

                //if (hasSearch)
                //{
                //    string searchLower = search.ToLower();
                //    vaccinesQuery = vaccinesQuery.Where(x =>
                //        (x.Vaccine.VaccineName != null && x.Vaccine.VaccineName.ToLower().Contains(searchLower)) ||
                //        (x.Vaccine.Description != null && x.Vaccine.Description.ToLower().Contains(searchLower)) ||
                //        (x.Vaccine.Manufacturer != null && x.Vaccine.Manufacturer.ToLower().Contains(searchLower))
                //    );
                //}

                //if (hasState)
                //{
                //    string stateLower = state.ToLower();
                //    vaccinesQuery = vaccinesQuery.Where(x =>
                //        x.Centre.State != null && x.Centre.State.ToLower().Contains(stateLower)
                //    );
                //}

                //if (hasCentre)
                //{
                //    string centreLower = centre.ToLower();
                //    vaccinesQuery = vaccinesQuery.Where(x =>
                //        x.Centre.CentreName != null && x.Centre.CentreName.ToLower().Contains(centreLower)
                //    );
                //}

                //List<Vaccine> result;
                //if (!hasSearch && !hasState && !hasCentre)
                //{
                //    result = ob.Vaccines.ToList();
                //}
                //else
                //{
                //    // ToList() here to force query execution before Distinct()
                //    result = vaccinesQuery
                //        .Select(x => x.Vaccine)
                //        .Distinct()
                //        .ToList();
                //}

              
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in VaccineSearch.");
                ViewBag.Error = "Search failed. Please try again.";
                return View("Vaccines", new List<Vaccine>());
            }
        }



        [HttpGet]
        public IActionResult Login()
        {
            try
            {
                var captchaCode = GenerateCaptchaCode(7);
                HttpContext.Session.SetString("CaptchaCode", captchaCode);
                return View();
            }catch(Exception ex)
            {

                logger.LogError(ex, "An error occurred in Login (GET).");
                return RedirectToAction("Error");
            }

        }


        [HttpPost]
        public IActionResult Login(string Username, string Password, string Captcha)
        {
            try
            {
                // Validate CAPTCHA 
                if (!IsCaptchaValid(Captcha))
                {
                    ViewBag.CaptchaError = "Invalid CAPTCHA.";
                    return View();
                }
                var sessionCaptcha = HttpContext.Session.GetString("CaptchaCode") ?? "";
                if (!string.Equals(Captcha, sessionCaptcha, StringComparison.OrdinalIgnoreCase))
                {
                    ModelState.AddModelError("Captcha", "Invalid captcha code. Please try again.");
                }
                var passwordBytes = System.Text.Encoding.UTF8.GetBytes(Password);
                var user = ob.Users.FirstOrDefault(u => u.Username == Username && u.Password.SequenceEqual(passwordBytes));

                var newCaptchaCode = GenerateCaptchaCode(5);
                HttpContext.Session.SetString("CaptchaCode", newCaptchaCode);
                ViewBag.CaptchaCode = newCaptchaCode;

                if (user != null)
                {
                    HttpContext.Session.SetString("UserId", user.UserId.ToString());
                    ViewBag.a = "Login Successful";
                    return RedirectToAction("UserDashboard");
                }
                else
                {
                    return RedirectToAction("Register");
                }
            }

            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in Login (POST).");
                ViewBag.CaptchaError = "Login failed.";
                return View();
            }

        }

        // Method to validate CAPTCHA 
        private bool IsCaptchaValid(string captcha)
        {
            // Implement your CAPTCHA validation logic here 
            // For example, compare with a stored value or use a CAPTCHA service 
            return captcha == HttpContext.Session.GetString("CaptchaCode");
        }


        [HttpGet]
        public IActionResult Captcha()
        {
            try
            {
                // Generate CAPTCHA code and store it in session 
                var captchaCode = GenerateCaptchaCode(7);
                HttpContext.Session.SetString("CaptchaCode", captchaCode);
                return Content(captchaCode);
            }
            catch (Exception ex)
            {

                logger.LogError(ex, "An error occurred in Login (GET).");
                return RedirectToAction("Error");
            }

        }

        // Method to generate CAPTCHA code 
        private string GenerateCaptchaCode(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, 6)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            try
            {
                return View();
            }
            catch (Exception ex)
            {

                logger.LogError(ex, "An error occurred in ForgotPassword (GET).");
                return RedirectToAction("Error");
            }

        }


        [HttpPost]
        public IActionResult ForgotPassword(string Username, string SecurityQuestion, string SecurityAnswer, string NewPassword)
        {
            try
            {
                var user = ob.Users.FirstOrDefault(u => u.Username == Username);

                if (user == null)
                {
                    ViewBag.Error = "Username not found.";
                    return View();
                }

                // Show question pre-filled 
                ViewBag.Username = Username;
                ViewBag.SecurityQuestion = user.SecurityQuestion;
                if (string.IsNullOrEmpty(SecurityAnswer))
                {
                    return View();
                }

                ViewBag.SecurityAnswer = SecurityAnswer;
                ViewBag.NewPassword = NewPassword;
                // Validate security answer 
                if (user.SecurityAnswer != SecurityAnswer)
                {
                    ViewBag.Error = "Incorrect security answer.";
                    return View();
                }

                if (!string.IsNullOrWhiteSpace(NewPassword))
                {
                    var bytes = System.Text.Encoding.UTF8.GetBytes(NewPassword);
                    user.Password = bytes;
                    ob.SaveChangesAsync();
                    TempData["Success"] = "Password set successfully!";
                    return RedirectToAction("Login");
                }
                // If answer is right but password is missing, prompt 
                ViewBag.AnswerVerified = true;
                return View();
            }

            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in ForgotPassword (POST).");
                ViewBag.Error = "Password reset failed.";
                return View();
            }

        }

        [HttpGet]
        public IActionResult ResetPassword()
        {
            try
            {
                return View();
            }
            catch (Exception ex)
            {

                logger.LogError(ex, "An error occurred in ResetPassword(GET).");
                return RedirectToAction("Error");
            }

        }

        [HttpPost]
        public IActionResult ResetPassword(string Username, string OldPassword, string NewPassword, string ConfirmPassword)
        {
            try
            {
                var user = ob.Users.FirstOrDefault(u => u.Username == Username);

                if (user == null)
                {
                    ViewBag.Error = "User not found.";
                    return View();
                }

                // Compare   old password 
                var oldpassword = System.Text.Encoding.UTF8.GetBytes(OldPassword);
                if (user.Password.SequenceEqual(oldpassword))
                {
                    ViewBag.Error = "Old password is incorrect.";
                    return View();
                }

                if (NewPassword != ConfirmPassword)
                {
                    ViewBag.Error = "New password and confirm password do not match.";
                    return View();
                }
                var newpassword = System.Text.Encoding.UTF8.GetBytes(NewPassword);

                // Update password 
                user.Password = newpassword;
                ob.SaveChangesAsync();

                TempData["Success"] = "Password Reset successfully!";
                return RedirectToAction("Login");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in ResetPassword (POST).");
                ViewBag.Error = "Password reset failed.";
                return View();
            }

        }

        [HttpGet]
        public IActionResult Register()
        {
            try
            {
                return View();
            }
            catch (Exception ex)
            {

                logger.LogError(ex, "An error occurred in Login (GET).");
                return RedirectToAction("Error");
            }

        }

        [HttpPost]
        public IActionResult Register(User u, string password, string securityQuestion)
        {
            try
            {
                // Validate password 
                if (string.IsNullOrEmpty(password))
                {
                    ModelState.AddModelError("Password", "Password is required.");
                    return View(u);
                }
                u.SecurityQuestion = securityQuestion;

                // Convert password string to byte array 
                u.Password = System.Text.Encoding.UTF8.GetBytes(password);
                try
                {
                    ob.Users.Add(u);
                    int i = ob.SaveChanges();

                    if (i != 0)
                    {
                        ViewBag.data = "Registration successfully";
                        return RedirectToAction("Login");
                    }
                }
                catch (Exception ex)
                {
                    ViewBag.data = "Registration Failed";
                }
                return View();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in Register.");
                ViewBag.data = "Registration Failed";
                return View("Register");
            }
        }


        [HttpPost]
        public IActionResult CancelBooking(int familyId)
        {
            try
            {
                int userId = Convert.ToInt32(HttpContext.Session.GetString("UserId"));

                var booking = ob.Bookings
                    .Where(b => b.FamilyId == familyId && b.Status == "Booked")
                    .OrderByDescending(b => b.BookingDate)
                    .FirstOrDefault();

                if (booking != null)
                {
                    booking.Status = "Cancelled";

                    var vaccine = ob.Vaccines.FirstOrDefault(v => v.VaccineId == booking.VaccineId);
                    if (vaccine != null && vaccine.Stock.HasValue)
                    {
                        vaccine.Stock += 1;
                        ob.SaveChangesAsync();
                    }
                }


                ob.SaveChangesAsync();
                return RedirectToAction("UserDashboard");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in Cancel Booking.");
                ViewBag.data = "Registration Failed";
                return View("UserDashboard");
            }

        }

        [HttpPost]
        public IActionResult CancelBookingForUser()
        {
            try
            {
                string userIdStr = HttpContext.Session.GetString("UserId");
                if (string.IsNullOrEmpty(userIdStr))
                {
                    return RedirectToAction("Login");
                }
                int userId = Convert.ToInt32(userIdStr);

                var booking = ob.Bookings
                    .Where(b => b.UserId == userId && b.FamilyId == null && b.Status == "Booked")
                    .OrderByDescending(b => b.BookingDate)
                    .FirstOrDefault();

                if (booking != null)
                {
                    booking.Status = "Cancelled";

                    var vaccine = ob.Vaccines.FirstOrDefault(v => v.VaccineId == booking.VaccineId);
                    if (vaccine != null && vaccine.Stock.HasValue)
                    {
                        vaccine.Stock += 1;
                    }
                    ob.SaveChangesAsync();
                }

                return RedirectToAction("UserDashboard");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in Cancel Booking For User.");
                ViewBag.data = "Registration Failed";
                return View("UserDashboard");
            }

        }


        [HttpGet]
        public IActionResult BookSlot(int familyId)
        {
            try
            {
                var family = ob.Families.FirstOrDefault(f => f.FamilyId == familyId);
                if (family == null) return NotFound();

                ViewBag.Family = family;
                ViewBag.Vaccines = ob.Vaccines.ToList();
                ViewBag.Centres = ob.Centres.ToList();
                return View();
            }
            catch (Exception ex)
            {

                logger.LogError(ex, "An error occurred in Login (GET).");
                return RedirectToAction("Error");
            }

        }


        [HttpPost]
        public IActionResult BookSlot(int familyId, int vaccineId, int centreId, DateTime slotDate, TimeSpan slotTime)
        {
            try
            {
                int userId = Convert.ToInt32(HttpContext.Session.GetString("UserId"));

                var vaccine1 = ob.Vaccines.FirstOrDefault(v => v.VaccineId == vaccineId);
                if (vaccine1 == null || !vaccine1.Stock.HasValue || vaccine1.Stock.Value <= 0)
                {
                    // Repopulate dropdowns and show error
                    ViewBag.Family = ob.Families.FirstOrDefault(f => f.FamilyId == familyId);
                    ViewBag.Vaccines = ob.Vaccines.ToList();
                    ViewBag.Centres = ob.Centres.ToList();
                    ViewBag.Error = "Selected vaccine is out of stock.";
                    return View();
                }

                var slot = ob.Slots.FirstOrDefault(s =>
                    s.VaccineId == vaccineId &&
                    s.CentreId == centreId &&
                    s.SlotDate == DateOnly.FromDateTime(slotDate) &&
                    s.SlotTime == TimeOnly.FromTimeSpan(slotTime));

                if (slot == null)
                {
                    slot = new Slot
                    {
                        VaccineId = vaccineId,
                        UserId = userId,
                        CentreId = centreId,
                        SlotDate = DateOnly.FromDateTime(slotDate),
                        SlotTime = TimeOnly.FromTimeSpan(slotTime),
                        FamilyId = familyId
                    };
                    ob.Slots.Add(slot);
                    ob.SaveChangesAsync();
                }



                var booking = ob.Bookings
                    .Where(b => b.FamilyId == familyId && b.Status == "Cancelled")
                    .OrderByDescending(b => b.BookingDate)
                    .FirstOrDefault();

                if (booking != null)
                {
                    booking.SlotId = slot.SlotId;
                    booking.VaccineId = vaccineId;
                    booking.BookingDate = DateTime.Now;
                    booking.Status = "Booked";
                    booking.PaymentMode = "Online";
                }
                else
                {
                    booking = new Booking
                    {
                        UserId = userId,
                        FamilyId = familyId,
                        SlotId = slot.SlotId,
                        VaccineId = vaccineId,
                        BookingDate = DateTime.Now,
                        Status = "Booked",
                        PaymentMode = "Online"
                    };
                    ob.Bookings.Add(booking);
                }

                var vaccine = ob.Vaccines.FirstOrDefault(v => v.VaccineId == vaccineId);
                if (vaccine != null && vaccine.Stock.HasValue && vaccine.Stock.Value > 0)
                {
                    vaccine.Stock -= 1;
                    ob.SaveChangesAsync();
                }

                ob.SaveChangesAsync();
                return RedirectToAction("UserDashboard");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in Booking Slot.");
                ViewBag.data = "Registration Failed";
                return View("UserDashboard");
            }

        }

        [HttpGet]
        public IActionResult BookSlotForUser(int? vaccineId = null)
        {
            try
            {
                int userId = Convert.ToInt32(HttpContext.Session.GetString("UserId"));
                var vaccine = ob.Vaccines.FirstOrDefault(v => v.VaccineId == vaccineId);
                if (vaccine == null || !vaccine.Stock.HasValue || vaccine.Stock.Value <= 0)
                {
                    // Repopulate dropdowns and show error
                    ViewBag.User = ob.Users.FirstOrDefault(u => u.UserId == userId);
                    ViewBag.Vaccines = ob.Vaccines.ToList();
                    ViewBag.Centres = ob.Centres.ToList();
                    ViewBag.SelectedVaccineId = vaccineId;
                    ViewBag.Error = "Selected vaccine is out of stock.";
                    return View();
                }

                var user = ob.Users.FirstOrDefault(u => u.UserId == userId);


                ViewBag.User = user;
                ViewBag.Vaccines = ob.Vaccines.ToList();
                ViewBag.Centres = ob.Centres.ToList();
                ViewBag.SelectedVaccineId = vaccineId;
                return View();
            }
            catch (Exception ex)
            {

                logger.LogError(ex, "An error occurred in BookSlotForUser.");
                return RedirectToAction("Error");
            }
        }


        [HttpPost]
        public IActionResult BookSlotForUser(int vaccineId, int centreId, DateTime slotDate, TimeSpan slotTime)
        {
            try
            {
                int userId = Convert.ToInt32(HttpContext.Session.GetString("UserId"));

                var slot = ob.Slots.FirstOrDefault(s =>
                    s.VaccineId == vaccineId &&
                    s.CentreId == centreId &&
                    s.SlotDate == DateOnly.FromDateTime(slotDate) &&
                    s.SlotTime == TimeOnly.FromTimeSpan(slotTime) &&
                    s.UserId == userId &&
                    s.FamilyId == null);

                if (slot == null)
                {
                    slot = new Slot
                    {
                        VaccineId = vaccineId,
                        UserId = userId,
                        CentreId = centreId,
                        SlotDate = DateOnly.FromDateTime(slotDate),
                        SlotTime = TimeOnly.FromTimeSpan(slotTime),
                        FamilyId = null
                    };
                    ob.Slots.Add(slot);
                    ob.SaveChangesAsync();
                }

                // Try to find a cancelled booking for the user
                var booking = ob.Bookings
                    .Where(b => b.UserId == userId && b.FamilyId == null && b.Status == "Cancelled")
                    .OrderByDescending(b => b.BookingDate)
                    .FirstOrDefault();

                if (booking != null)
                {
                    // Update the cancelled booking
                    booking.SlotId = slot.SlotId;
                    booking.VaccineId = vaccineId;
                    booking.BookingDate = DateTime.Now;
                    booking.Status = "Booked";
                    booking.PaymentMode = "Online";
                }
                else
                {
                    // Create a new booking
                    booking = new Booking
                    {
                        UserId = userId,
                        FamilyId = null,
                        SlotId = slot.SlotId,
                        VaccineId = vaccineId,
                        BookingDate = DateTime.Now,
                        Status = "Booked",
                        PaymentMode = "Online"
                    };
                    ob.Bookings.Add(booking);
                }

                var vaccine = ob.Vaccines.FirstOrDefault(v => v.VaccineId == vaccineId);
                if (vaccine != null && vaccine.Stock.HasValue && vaccine.Stock.Value > 0)
                {
                    vaccine.Stock -= 1;
                    ob.SaveChangesAsync();
                }

                ob.SaveChangesAsync();

                return RedirectToAction("UserDashboard");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in Booking Slot.");
                ViewBag.data = "Registration Failed";
                return View("UserDashboard");
            }

        }


        private readonly ILogger<VaccineController> logger;

        public VaccineController(ILogger<VaccineController> logger)
        {
            this.logger = logger;
        }

        public IActionResult Error()
        {
            var exceptionFeature = HttpContext.Features.Get<IExceptionHandlerFeature>();
            if (exceptionFeature != null)
            {
                // Log the exception details 
                logger.LogError(exceptionFeature.Error, "An error occurred.");
            }
            return View("Error");
        }

        //[HttpGet]
        public IActionResult ProjectHome()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
            Response.Headers["Pragma"] = "no-cache";
            Response.Headers["Expires"] = "-1";

            return RedirectToAction("Login", "Vaccine");
        }

        [HttpGet]
        public IActionResult Feedback()
        {
            return View();
        }

    }

    public class ForgotPasswordViewModel
    {
        public string SecurityAnswer { get; internal set; }
        public object NewPassword { get; internal set; }
        public object ConfirmPassword { get; internal set; }
        public string Username { get; internal set; }
        public String SecurityQuestion { get; internal set; }
    }
}





