# auth server

```shell
curl -X GET http://localhost:3333/v1/users/otp \
--header 'Content-Type: application/json' \
--header 'Authorization: Basic ZHJpdmVyLWFwcDpkcml2ZXItYXBwLXNlY3JldA==' -v
```
->
```shell
{"code":"ABCDEF"}
```
---
```shell
curl -X POST http://localhost:3333/oauth2/token\?grant_type\=otp&code=ABCDEF \
--header 'Content-Type: application/json' \
--header 'Authorization: Basic ZHJpdmVyLWFwcDpkcml2ZXItYXBwLXNlY3JldA==' -v
```
->
```shell
{
  "access_token":"eyJraWQiOiIwZDE5NGFjOC1iMDA4LTQxYzYtOGRjNy05OTYyZTRlZWIyODQiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkcml2ZXItYXBwIiwiYXVkIjoiZHJpdmVyLWFwcCIsIm5iZiI6MTcwNTA0MDA2NSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDozMzMzIiwiZXhwIjoxNzA2MjQ5NjY1LCJpYXQiOjE3MDUwNDAwNjUsImp0aSI6ImQxMmNkN2VjLTE2M2MtNGU2Ni05NTYyLTQ4NGYyNzNhMjg2ZiJ9.ct9N9Tq80pgtthJanXVW6Ak32vcD8HTZDiV-ym6Js64-SXSGiwrc3PvO5MF7AsBW366VvYj5kMdHDK8T8rGlXH76t5i8Z9cdqIUSGBNVHnJo6YTedrJ89cc319BtB3RaoGRPgOipiTCLQtuUa05JVAJ5Y5ecbasCIE2X5JojPGQSBk7sc6GDE4gN2TBxqXgPqKEAkjzmfabm9-wzbk1i70HFrsxuSxF4X0rFEimIN8M5e-k3BeFqmYDWHNSVJpp8QL69yVRxRLRNlmUmV6nPMul4PUrrkwc105jpKSRCAnRSmigeRkY_Q5PgRV-u2QdiZF89NonJrz2WWOSjF0zm1w",
  "refresh_token":"w41nYJqLKiW4wRcsFTHg6ybHSvTsLjUg772g0ZooLLF63TXr2AhHtI3qpllozdjL8yreqvxGzp-4mdqGWpjn5dDYtJ-P3Ivqlw5tqkBWh3zebCGpMaE9LpEOnpRHnZdG",
  "token_type":"Bearer",
  "expires_in":1209599
}
```
---
```shell
curl -X GET localhost:3333/v1/users/me \
--header 'Authorization: Bearer eyJraWQiOiIwZDE5NGFjOC1iMDA4LTQxYzYtOGRjNy05OTYyZTRlZWIyODQiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkcml2ZXItYXBwIiwiYXVkIjoiZHJpdmVyLWFwcCIsIm5iZiI6MTcwNTA0MDA2NSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDozMzMzIiwiZXhwIjoxNzA2MjQ5NjY1LCJpYXQiOjE3MDUwNDAwNjUsImp0aSI6ImQxMmNkN2VjLTE2M2MtNGU2Ni05NTYyLTQ4NGYyNzNhMjg2ZiJ9.ct9N9Tq80pgtthJanXVW6Ak32vcD8HTZDiV-ym6Js64-SXSGiwrc3PvO5MF7AsBW366VvYj5kMdHDK8T8rGlXH76t5i8Z9cdqIUSGBNVHnJo6YTedrJ89cc319BtB3RaoGRPgOipiTCLQtuUa05JVAJ5Y5ecbasCIE2X5JojPGQSBk7sc6GDE4gN2TBxqXgPqKEAkjzmfabm9-wzbk1i70HFrsxuSxF4X0rFEimIN8M5e-k3BeFqmYDWHNSVJpp8QL69yVRxRLRNlmUmV6nPMul4PUrrkwc105jpKSRCAnRSmigeRkY_Q5PgRV-u2QdiZF89NonJrz2WWOSjF0zm1w' -v
```
->
```shell
{"id":"Justin"}
```
