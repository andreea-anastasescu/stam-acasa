using System;
using System.Linq;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1.Cms;
using StamAcasa.Api.Extensions;
using StamAcasa.Api.Models;
using StamAcasa.Api.Services;
using StamAcasa.Common.DTO;
using StamAcasa.Common.Services;

namespace StamAcasa.Api.Controllers
{
    [Authorize(AuthenticationSchemes = "answersApi")]
    [Route("api/[controller]")]
    [ApiController]
    public class FormController : ControllerBase
    {
        private readonly IFileService _fileService;
        private readonly IFormService _formService;
        private readonly IUserService _userService;
        private readonly IAssessmentService _assessmentService;

        public FormController(IFileService fileService, IFormService formService, IUserService userService, IAssessmentService assessmentService)
        {
            _fileService = fileService;
            _formService = formService;
            _userService = userService;
            _assessmentService = assessmentService;
        }

        [HttpGet]
        public async Task<IActionResult> Get(int? id = null)
        {
            var subClaimValue = User.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
            if (subClaimValue == null)
                return new UnauthorizedResult();

            var authenticatedUser = await _userService.GetUserInfo(subClaimValue);
            var isRequestAllowed = await IsRequestAllowed(id, authenticatedUser);
            if (isRequestAllowed.NotAllowed)
            {
                return isRequestAllowed.Result;
            }

            var result =
              id.HasValue ?
                  await _formService.GetForms(id.Value) :
                  await _formService.GetForms(subClaimValue);

            return new OkObjectResult(result);
        }


        [HttpGet("version")]
        public async Task<IActionResult> GetVersion([FromQuery(Name = "userId")] int? userId)
        {
            var subClaimValue = User.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
            if (subClaimValue == null)
                return new UnauthorizedResult();

            var assessment = await _assessmentService.GetAssessment(subClaimValue, userId);

            return new OkObjectResult(assessment);
        }

        [HttpPost]
        public async Task<IActionResult> PostAnswer([FromBody]UserForm form, [FromQuery]int? id = null)
        {
            var subClaimValue = User.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
            if (subClaimValue == null)
                return new UnauthorizedResult();

            
            var authenticatedUser = await _userService.GetUserInfo(subClaimValue);
            var isRequestAllowed =  await IsRequestAllowed(id, authenticatedUser);
            if (isRequestAllowed.NotAllowed)
            {
                return isRequestAllowed.Result;
            }

            // TODO: add user profile info as added properties to form, before save

            var contentToSave = JsonConvert.SerializeObject(form).ToString();

            await _formService.AddForm(new FormInfo
            {
                Content = contentToSave,
                Timestamp = form.Timestamp.ToDateTimeFromEpoch(),
                UserId = id ?? authenticatedUser.Id,
                FormTypeId = form.FormId.ToString()
            });

            await _fileService.SaveRawData(contentToSave,
                $"{Guid.Parse(subClaimValue).ToString("N")}_{form.FormId}_{form.Timestamp}.json");

            return new OkObjectResult(string.Empty);
        }

        private async Task<(bool NotAllowed, IActionResult Result)> IsRequestAllowed(int? id, UserInfo authenticatedUser)
        {
            if (authenticatedUser == null)
            {
                return (true, NotFound("Could not find authenticated user"));
            }
            if (id.HasValue)
            {
                var currentUser = await _userService.GetUserInfo(id.Value);
                if (currentUser == null)
                {
                    return (true, NotFound($"Could not find user with id {id.Value}"));
                }

                var notFamilyMember = (currentUser.ParentId.HasValue && currentUser.ParentId != authenticatedUser.Id) || !currentUser.ParentId.HasValue;
                if (authenticatedUser.Id != currentUser.Id && notFamilyMember)
                    return (true, new StatusCodeResult(StatusCodes.Status403Forbidden));
            }

            return (false, null);
        }
    }
}