using PasswordManager.Common;
using PasswordManager.Dto.Credentials;

namespace PasswordManager.Interfaces.Credentials
{
    public interface ICredentialService
    {
        Task<ReturnResponse<GetCredDetailsDto>> AddCredential(AddCredDto addCred, string authToken);
        Task<ReturnResponse<GetCredDetailsDto>> UpdateCredential(Guid credId,EditCredDto editCredDto, string authToken);
        Task<ReturnResponse> DeleteCredential(Guid credId, string authToken);
        Task<ReturnResponse<GetCredDetailsDto>> GetCredentialDetail(Guid credId, string authToken);
        Task<ReturnResponse<List<GetCredDetailsDto>>> GeAllCredential(string authToken);
    }
}
