# awsSTS

**AWS Security Token Service API in Nim**

This nim package is for generating AWS Security Token Service and temporary
ASIAxxx credentials.

AWS Security Token Service (AWS STS) is a web service that enables you to
request temporary, limited-privilege credentials for AWS Identity and Access
Management (IAM) users or for users that you authenticate (federated users).

This package is purely for generating ASIAxxxx credentials, which can be used
in other services.


# Example

## General one time call

```nim
import awsSTS

awsSTSInitHttpPool(size = 5)

let
  myAccessKey   = "AKIDEXAMPLE"
  mySecretKey   = "23456OIUYTREXAMPLE"
  role          = "arn:aws:iam::87654322345:role/Role-I-Can-And-May"
  serverRegion  = "eu-west-1"

let creds = awsSTScreateASIA(myAccessKey, mySecretKey, serverRegion, role)

echo creds.AWS_ACCESS_KEY_ID
echo creds.AWS_SECRET_ACCESS_KEY
echo creds.AWS_SESSION_TOKEN
```

## Keep in global variable and auto-renew

Auto-renew and keep credentials in global variable. Accessible from all threads.

```nim
import awsSTS/sts

awsSTSInitHttpPool(size = 5)

let
  myAccessKey   = "AKIDEXAMPLE"
  mySecretKey   = "23456OIUYTREXAMPLE"
  role          = "arn:aws:iam::87654322345:role/Role-I-Can-And-May"
  serverRegion  = "eu-west-1"

let creds = stsGet(myAccessKey, mySecretKey, serverRegion, role)

echo creds.AWS_ACCESS_KEY_ID
echo creds.AWS_SECRET_ACCESS_KEY
echo creds.AWS_SESSION_TOKEN
```



# Reusable HttpClient pool

In version 2.1.0, an HTTP pool was implemented to handle HTTP requests.
The pool includes monitoring of consecutive errors, age of clients, and number of requests.
Based on these, the clients will be recycled.

The pool requires initialization with `awsSTSInitHttpPool(size = 5)`.

The pool is **enabled** by default when using `--threads:on` (so always in
Nim v2.x). The pool is **disabled** when using `-d:disableAwsStsHttpPool` and
the method reverts back to using an individual HttpClient for each call.

When running single-threaded, the pool is disabled by default. To enable the pool,
use `-d:awsStsHttpPool`.

On initialization, the pool will echo status. Disable this with
`-d:awsStsHttpPoolNoEcho`.



# Changelog

## 2.1.0

* Added http pool for reusing http clients.
* Made `awsSTScreateASIA` public, so the wrapper `awsSTScreate` is not needed.

## v1.0.4

Replacing dependency `sigv4` with `awsSigV4`. The allows us to ignore the
dependency `balls`.

`awsCredsMonitor()` has been removed.





