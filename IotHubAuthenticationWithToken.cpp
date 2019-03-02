#include <mbed.h>
#include "url_encode.h"
#include "IotHubAuthenticationWithToken.h"
#include "mbed_trace.h"

#define SAS_AUDIENCE_FORMAT						"%s/devices/%s"
#define SAS_TOKEN_FORMAT						"SharedAccessSignature sr=%s&sig=%s&se=%lu"
#define SAS_SIGN_REQUEST_FORMAT					"%s\n%lu"

#ifndef _min
#define _min(n1,n2) (n1 < n2 ? n1 : n2)
#endif

IotHubAuthenticationWithToken::IotHubAuthenticationWithToken(char *hostname, char *device_id, uint32_t ttl_sec)
	: _hostname(hostname)
	, _device_id(device_id)
	, _token(NULL)
	, expiry(0)
	, _ttl_sec(ttl_sec)
{
}

IotHubAuthenticationWithToken::~IotHubAuthenticationWithToken()
{
	free(_token);
	_token = NULL;
}

void IotHubAuthenticationWithToken::populate_from(IotHubConnectionString *cs)
{
	_hostname = cs->get_hostname();
	_device_id = cs->get_device_id();
}

void IotHubAuthenticationWithToken::populate_to(IotHubConnectionString *cs)
{
	cs->with_hostname(_hostname);
	cs->with_device_id(_device_id);
}

char* IotHubAuthenticationWithToken::make_audience()
{
	// determine amount of memory required for the raw audience
	size_t aud_raw_sz = snprintf(NULL, 0, SAS_AUDIENCE_FORMAT, _hostname, _device_id);
	aud_raw_sz++; // allow for NULL character at the end
	
	// make the raw audience
	char *aud_raw = (char *)malloc(aud_raw_sz); // TODO: check for NULL
	memset(aud_raw, 0, aud_raw_sz);
	aud_raw_sz = snprintf(aud_raw, aud_raw_sz, SAS_AUDIENCE_FORMAT, _hostname, _device_id);
	
	// determine amount of memory required for the encoded audience
	size_t aud_sz = url_encode(aud_raw, aud_raw_sz, NULL, 0);
	aud_sz++; // allow for NULL character at the end
	
	// make the encoded audience
	char *aud = (char *)malloc(aud_sz); // TODO: check for NULL
	memset(aud, 0, aud_sz);
	aud_sz = url_encode(aud_raw, aud_raw_sz, aud, aud_sz);
	
	// free raw audience
	free(aud_raw);

	return aud;
}

char* IotHubAuthenticationWithToken::make_request(const char *aud, uint32_t exp, size_t *rlen)
{
	// determine amount of memory required for the request
	size_t req_sz = snprintf(NULL, 0, SAS_SIGN_REQUEST_FORMAT, aud, exp);
	req_sz++; // allow for NULL character at the end
	
	// make the request
	char *req = (char *)malloc(req_sz); // TODO: check for NULL
	memset(req, 0, req_sz);
	*rlen = snprintf(req, req_sz, SAS_SIGN_REQUEST_FORMAT, aud, exp);
	
	return req;
}

char* IotHubAuthenticationWithToken::make_signature(const char *request, size_t rlen)
{
	// generate raw signature
	size_t sig_raw_len = 0, sig_raw_sz = 200;
	char *sig_raw = (char *)malloc(sig_raw_sz); // TODO: check for NULL
	memset(sig_raw, 0, sig_raw_sz);
	sign(request, rlen, sig_raw, sig_raw_sz, &sig_raw_len);
	
	// determine amount of memory required for the encoded signature
	size_t sig_sz = url_encode(sig_raw, sig_raw_len, NULL, 0);
	sig_sz++; // allow for NULL character at the end
	
	// make the encoded signature
	char *sig = (char *)malloc(sig_sz); // TODO: check for NULL
	memset(sig, 0, sig_sz);
	sig_sz = url_encode(sig_raw, sig_raw_len, sig, sig_sz);
	
	// free raw signature
	free(sig_raw);

	return sig;
}

char* IotHubAuthenticationWithToken::make_token(const char *aud, const char *sig)
{
	// determine amount of memory required for token
	size_t token_len = snprintf(NULL, 0, SAS_TOKEN_FORMAT, aud, sig, (uint32_t)expiry);
	token_len++; // allow for NULL character at the end
	
	// make the token
	char *token = (char *)malloc(token_len); // TODO: check for NULL
	memset(token, 0, token_len);
	token_len = snprintf(token, token_len, SAS_TOKEN_FORMAT, aud, sig, (uint32_t)expiry);
	return token;
}

char* IotHubAuthenticationWithToken::get_password()
{
	// prevent other threads from accessing this function until it completes
	_mtx_token.lock();
	
	/*
	 * STEP 1: check if the current one has expired.
	 * If not do not proceed.
	 * */
	if (is_valid())
	{
		_mtx_token.unlock(); // release lock
		return _token;		
	}

	// at this point, we cannot use the password that exists so we need to free it
	if(_token != NULL)
	{
		free(_token);
		_token = NULL;
	}
	
	/*
	 * STEP 2: make the expiry time (seconds)
	 * This function assumes that the standard time functions are implemented by the platform
	 * */
	expiry = time(NULL); // do not use now because it may have changed
	expiry += _ttl_sec;
	if ((expiry % 10) == 0) expiry += 1; // INVESTIGATE: signing step below fails if the last digit is zero
	
	/* 
     * STEP 3: form the audience
     * */
	char *aud = make_audience();
	
	/* 
	 * STEP 4: form the request using the audience
	 * */
	size_t request_len;
	char *req = make_request(aud, expiry, &request_len);
	
	/* 
	 * STEP 4: sign the request
	 * */
	char *sig = make_signature(req, request_len);
	
	/* 
	 * STEP 5: form the complete SAS using the audience, the signature and the expiry.
	 * */
	char *token = make_token(aud, sig);
	
	/* 
	 * STEP 6: free created resources
	 * */
	free(aud);
	free(req);
	free(sig);
	
	/* 
	 * STEP 7: save token
	 * */
	_token  = token;
	_mtx_token.unlock(); // release lock
	
	return _token;
}

time_t IotHubAuthenticationWithToken::get_expiry()
{
	return expiry;
}

bool IotHubAuthenticationWithToken::is_valid()
{
	// without a token or if there is no expiry set, then it has expired
	if(_token == NULL || expiry <= 0) return false;
	
	// set expired threshold at 80% of lifetime but not with more than 5 min remaining
	uint32_t expired_threshold = (_ttl_sec - _min((_ttl_sec / 5), 300));
	
	// get the time after which we should renew
	time_t renew_at = expiry - expired_threshold;
	
	// get the time right now
	time_t now = time(NULL);
	
	// the token is valid if the time we should renew is in the future (i.e. greater than now)
	return renew_at < now;
}
