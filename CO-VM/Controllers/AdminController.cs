using CO_VM.Models;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Diagnostics;

namespace CO_VM.Controllers
{
    public class AdminController : Controller
    {
        vaccineManagementContext vm = new vaccineManagementContext();
        public IActionResult Index()
        {
            try
            {
                return View();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in Index.");
                return RedirectToAction("Vaccine","Error");

            }

        }

        private byte[] HashPassword(string password)
        {

            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(Encoding.UTF8.GetBytes(password));
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
            // Generate CAPTCHA code and store it in session 
            var captchaCode = GenerateCaptchaCode(7);
            HttpContext.Session.SetString("CaptchaCode", captchaCode);
            return Content(captchaCode);
        }

        // Method to generate CAPTCHA code 
        private string GenerateCaptchaCode(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, 6).Select(s => s[random.Next(s.Length)]).ToArray());
        }

        [HttpGet]
        public IActionResult AdminLogin()
        {
            try
            {
                var captchaCode = GenerateCaptchaCode(7);
                HttpContext.Session.SetString("CaptchaCode", captchaCode);
                return View();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in AdminLogin.");
                return RedirectToAction("Vaccine", "Error");

            }

        }
        [HttpPost]
        public IActionResult AdminLogin(string Username, string Password, string Captcha)
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
                var newCaptchaCode = GenerateCaptchaCode(5);
                HttpContext.Session.SetString("CaptchaCode", newCaptchaCode);
                ViewBag.CaptchaCode = newCaptchaCode;
                // var passwordBytes = System.Text.Encoding.UTF8.GetBytes(Password);


                //byte[] adminpassword = Password as byte[];
                byte[] adminpassword = HashPassword(Password);
                var admin = vm.Admins.FirstOrDefault(a => a.Username == Username && a.Password.SequenceEqual(adminpassword));
                if (admin != null)
                {
                    ViewBag.a = "Login Successful";
                    HttpContext.Session.SetString("Role", "Admin");
                    HttpContext.Session.SetString("Username", admin.Username);
                    return RedirectToAction("Index");
                }
                else
                {
                    ViewBag.a = "User Not Found Please Register";
                    return View();
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in AdminLogin (POST).");
                ViewBag.CaptchaError = "Admin Login failed.";
                return View();
            }
            
        }

        [HttpGet]
        public IActionResult AddUser()
        {
            try
            {
                return View();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in AddUser.");
                return RedirectToAction("Vaccine", "Error");

            }

        }

        [HttpPost]
        public IActionResult AddUser(IFormCollection form)
        {
            try
            {
                User user = new User
                {
                    FullName = form["FullName"],
                    Email = form["Email"],
                    Password = Encoding.UTF8.GetBytes(form["Password"]),
                    PhoneNumber = form["PhoneNumber"],
                    AadhaarNo = form["AadhaarNo"],
                    Username = form["Username"],
                    Dob = DateOnly.Parse(form["Dob"]),
                    City = form["City"],
                    State = form["State"],
                    Gender = form["Gender"],
                    Address = form["Address"],
                    SecurityQuestion = form["SecurityQuestion"],
                    SecurityAnswer = form["SecurityAnswer"]
                };
                if (ModelState.IsValid)
                {
                    try
                    {
                        vm.Add(user);
                        vm.SaveChanges();
                        return RedirectToAction("Vaccines");
                    }
                    catch (Exception ex)
                    {
                        ViewBag.ErrorMessage = "User Already Exists " + ex.Message;
                    }
                }
                return View(user);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in AddUser (POST).");
                ViewBag.CaptchaError = "Add Userfailed.";
                return View();
            }

        }


        [HttpGet]
        public IActionResult UpdateUser(int? id)
        {
            try
            {
                if (id == null)
                {
                    return View();
                }
                var user = vm.Users.FirstOrDefault(u => u.UserId == id);
                if (user == null)
                {
                    ViewBag.Error = "User Not Found";
                    return View();
                }
                return View(user);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in UpdateUser.");
                return RedirectToAction("Vaccine", "Error");

            }

        }

        [HttpPost]
        public IActionResult UpdateUser(User upduse)
        {
            try
            {
                var user = vm.Users.FirstOrDefault(u => u.UserId == upduse.UserId);
                if (user != null)
                {
                    if (!string.IsNullOrWhiteSpace(upduse.FullName))
                        user.FullName = upduse.FullName;

                    if (!string.IsNullOrWhiteSpace(upduse.Username))
                        user.Username = upduse.Username;

                    if (!string.IsNullOrWhiteSpace(upduse.Email))
                        user.Email = upduse.Email;

                    if (!string.IsNullOrWhiteSpace(upduse.Address))
                        user.Address = upduse.Address;

                    if (!string.IsNullOrWhiteSpace(upduse.City))
                        user.City = upduse.City;

                    if (!string.IsNullOrWhiteSpace(upduse.State))
                        user.State = upduse.State;

                    if (!string.IsNullOrWhiteSpace(upduse.PhoneNumber))
                        user.PhoneNumber = upduse.PhoneNumber;

                    if (!string.IsNullOrWhiteSpace(upduse.AadhaarNo))
                        user.AadhaarNo = upduse.AadhaarNo;

                    vm.SaveChanges();
                    ViewBag.Success = "User updated successfully";
                }
                return View(user);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in UpdateUser (POST).");
                ViewBag.CaptchaError = "Update User failed.";
                return View();
            }

        }

        [HttpGet]
        public IActionResult DeleteUser(int id)
        {
            try
            {
                TempData["id"] = id;
                if (id == null)
                {
                    return View();
                }
                var user = vm.Users.FirstOrDefault(u => u.UserId == id);
                if (user == null)
                {
                    ViewBag.Error = "User Not Found";
                    return View();
                }
                return View(user);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in UpdateUser.");
                return RedirectToAction("Vaccine", "Error");

            }

        }

        [HttpPost]
        public IActionResult DeleteUser(IFormCollection f)
        {
            try{
                int id = Convert.ToInt32(TempData["id"]);
                var user = vm.Users.Find(id);
                if (user == null)
                {
                    return NotFound();
                }
                vm.Users.Remove(user);
                vm.SaveChanges();
                return View();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in DeleteUser (POST).");
                ViewBag.CaptchaError = "Delete User  failed.";
                return View();
            }

        }

        [HttpGet]
        public IActionResult ViewUser()
        {
            try
            {
                var users = vm.Users.ToList();
                return View(users);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in ViewUser.");
                return RedirectToAction("Vaccine", "Error");

            }

        }


        [HttpGet]
        public IActionResult AddVaccine()
        {
            try
            {
                return View();

            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in ViewUser.");
                return RedirectToAction("Vaccine", "Error");

            }

        }
        [HttpPost]
        public IActionResult AddVaccine(Vaccine v, IFormCollection f)
        {
            try
            {
                Vaccine vc = new Vaccine();
                vc.VaccineName = v.VaccineName;
                vc.Manufacturer = v.Manufacturer;
                vc.DosesRequired = v.DosesRequired;
                vc.Stock = v.Stock;
                var image = f.Files["imagefile"];
                if (image != null && image.Length > 0)
                {
                    using (var ms = new MemoryStream())
                    {
                        image.CopyTo(ms);
                        byte[] imagedata = ms.ToArray();
                        vc.Image = imagedata;
                    }
                }
                vc.Price = v.Price;
                vc.Description = v.Description;
                vm.Add(vc);
                vm.SaveChanges();
                return RedirectToAction("AdminHome");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in AddVaccine (POST).");
                ViewBag.CaptchaError = "Add Vaccine failed.";
                return View();
            }

        }

        [HttpGet]
        public IActionResult UpdateVaccine(int? id)
        {
            try
            {
                if (id == null)
                {
                    return View();
                }
                var vac = vm.Vaccines.FirstOrDefault(v => v.VaccineId == id);
                if (vac == null)
                {
                    ViewBag.Error = "User Not Found";
                    return View();
                }
                return View(vac);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in UpdateVaccine.");
                return RedirectToAction("Vaccine", "Error");

            }

        }
        [HttpPost]
        public IActionResult UpdateVaccine(Vaccine upd)
        {
            try
            {
                var vac = vm.Vaccines.FirstOrDefault(v => v.VaccineId == upd.VaccineId);
                if (vac != null)
                {
                    if (!string.IsNullOrWhiteSpace(upd.VaccineName))
                        vac.VaccineName = upd.VaccineName;

                    if (!string.IsNullOrWhiteSpace(upd.Manufacturer))
                        vac.Manufacturer = upd.Manufacturer;

                    vac.DosesRequired = upd.DosesRequired;
                    vac.Stock = upd.Stock;

                    if (upd.Image != null && upd.Image.Length > 0)
                        vac.Image = upd.Image; // Only update if a new image is provided 
                    vac.Price = upd.Price;
                    vac.Description = upd.Description;
                    vm.Vaccines.Update(vac);
                    vm.SaveChanges();
                    ViewBag.s = "Vaccine Updated Successfully";
                }
                else
                {
                    ViewBag.s = "Vaccine not found";
                }
                return View(vac);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in UpdateVaccine (POST).");
                ViewBag.CaptchaError = "Update Vaccine failed.";
                return View();
            }

        }


        [HttpGet]
        public IActionResult ViewVaccine()
        {
            try
            {
                var vaccines = vm.Vaccines.ToList();
                return View(vaccines);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in ViewVaccine.");
                return RedirectToAction("Vaccine", "Error");

            }

        }

        [HttpGet]
        public IActionResult DeleteVaccine(int id)
        {
            try
            {
                TempData["id"] = id;
                if (id == null)
                {
                    return View();
                }
                var vac = vm.Vaccines.FirstOrDefault(v => v.VaccineId == id);
                if (vac == null)
                {
                    ViewBag.Error = "User Not Found";
                    return View();
                }
                return View(vac);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in DeleteVaccine.");
                return RedirectToAction("Vaccine", "Error");

            }

        }
        [HttpPost]
        public IActionResult DeleteVaccine(IFormCollection f)
        {
            try
            {
                int id = Convert.ToInt32(TempData["id"]);
                var vac = vm.Vaccines.Find(id);
                if (vac == null)
                {
                    return NotFound();
                }
                vm.Vaccines.Remove(vac);
                vm.SaveChanges();
                return View();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in Delete Vaccine (POST).");
                ViewBag.CaptchaError = "Delete Vaccine failed.";
                return View();
            }

        }

        [HttpGet]
        public IActionResult Logout()
        {
            try
            {
                HttpContext.Session.Clear();
                Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
                Response.Headers["Pragma"] = "no-cache";
                Response.Headers["Expires"] = "-1";

                return RedirectToAction("Login", "Vaccine");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred in Logout.");
                return RedirectToAction("Vaccine", "Error");

            }

        }

        private readonly ILogger<AdminController> logger;

        public AdminController(ILogger<AdminController> logger)
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
            return View("Vaccine","Error");
        }
    }
}
