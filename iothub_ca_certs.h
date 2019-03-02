#ifndef __IOTHUB_CA_CERTS_H
#define __IOTHUB_CA_CERTS_H

#include <stddef.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PEM_PARSE_C)
#define MSIT_CA                                                         \
"-----BEGIN CERTIFICATE-----\r\n"                                       \
"MIIFtDCCBJygAwIBAgIQCLh6UBu+nNotFk0+OVG/VTANBgkqhkiG9w0BAQsFADBa\r\n"  \
"MQswCQYDVQQGEwJJRTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJl\r\n"  \
"clRydXN0MSIwIAYDVQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTE2\r\n"  \
"MDUyMDEyNTEyOFoXDTI0MDUyMDEyNTEyOFowgYsxCzAJBgNVBAYTAlVTMRMwEQYD\r\n"  \
"VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy\r\n"  \
"b3NvZnQgQ29ycG9yYXRpb24xFTATBgNVBAsTDE1pY3Jvc29mdCBJVDEeMBwGA1UE\r\n"  \
"AxMVTWljcm9zb2Z0IElUIFRMUyBDQSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A\r\n"  \
"MIICCgKCAgEAjvPxhHV3vL7JpPUWpVMrUGCZ3Nh92SS14XJJN0j+2oaTo30dmksQ\r\n"  \
"TXd5fmWpfG424kfUNknQzCQCJxTirnHN2Vd0PBBWGZJKh2L545CNXt7RQRsaph9A\r\n"  \
"oiwejlXXJthoQqvsDd7dXmGVs6xsgc6o4K2vX8qm5FFoLif9VCpxpMy7fpLx9lNR\r\n"  \
"BTHQGYKwymPQ8koAC830aUv0WpZWOSbJnUsKYzQygKUE5eoot8EAwG0a8CjUSo+A\r\n"  \
"rHMZ2PUWL62uCJdiBiz+56XwrUFTf40rMcMUcyHd43hjnFGGtaJIScB5CBVDACuZ\r\n"  \
"uEvgx1cHbMS5plQtAVPyo/KkzNnBVPOIzeRME9OKMyFYrRi/vjmBcDlpN/hbpGPv\r\n"  \
"CQffhxpix5oIxdEdXmJ2Ad1p5ji7RLAtTTrGLoDgYHJb8szmjlw6IR5dsDkrveoT\r\n"  \
"y5bLtmp0jI68DhCfG6VAQY+RXHanDvGqOoe3DHffcWovKGFCLZAPcgWrZ+DBe8uc\r\n"  \
"QJrECghEjHw9uqkOHrHZIr0fX0Fqc1T2ZuKg+aY53tJ382kEv7e7PMST/3IEHLU2\r\n"  \
"nWh/3/o5T7L2j7kc/63tDhUI44Z88khJd5cW9v0A9k+mXm/nOcBRZT3rsZcw7Oqe\r\n"  \
"c/weLKDfi89zX7UOBkIXJpXs2Kkn0NBllFziP8ooKaUg9MjdXbT/5t0CAwEAAaOC\r\n"  \
"AUIwggE+MB0GA1UdDgQWBBRYiJ/W3JxIIrcUPv+EiOjmhf/6fTAfBgNVHSMEGDAW\r\n"  \
"gBTlnVkwgkdYzKz6CFQ2hns6tQRN8DASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1Ud\r\n"  \
"DwEB/wQEAwIBhjAnBgNVHSUEIDAeBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUF\r\n"  \
"BwMJMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln\r\n"  \
"aWNlcnQuY29tMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0\r\n"  \
"LmNvbS9PbW5pcm9vdDIwMjUuY3JsMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsG\r\n"  \
"AQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA0GCSqGSIb3DQEB\r\n"  \
"CwUAA4IBAQAwmsadav3vkwgMvoJ3+XagbZ57MCN7qCla9Go+xwsMlt+4S1LkDZw4\r\n"  \
"7XhjtXPAHB874Kf/f0lRlTK40Jup5c+WA4GA1UphGP7Easbff0FGIpyAZusPQqDk\r\n"  \
"86Qho5jQenT2jOjD0iuqK84RWRlE51wHCULr1/0VTblvbEQ1Joe6oztosIHnIMl/\r\n"  \
"EwLzzKufHJVQy65kgLuHCl3OpmuyfeM9NuIpUbcl/NAJ47CtxGIuPn6FJrL2r/dt\r\n"  \
"MXPGGZipcpMCzsoLPTzs2XDogPUWq3hqh03GgTeoCnaBBqjvF2B8cBATPDjXM0zk\r\n"  \
"N2UI+5Gz6BZ2YSpl9ViUs0UB78BPA3u4\r\n"                                  \
"-----END CERTIFICATE-----\r\n"


/* Concatenation of all additional CA certificates in PEM format if available */
const char   iothub_ca_chain_pem[] = MSIT_CA;
const size_t iothub_ca_chain_pem_len = sizeof(iothub_ca_chain_pem);
#endif

#endif /* __IOTHUB_CA_CERTS_H */
