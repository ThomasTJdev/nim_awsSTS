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

```nim
let
  myAccessKey   = "AKIDEXAMPLE"
  mySecretKey   = "23456OIUYTREXAMPLE"
  role          = "arn:aws:iam::87654322345:role/Role-I-Can-And-May"
  serverRegion  = "eu-west-1"

let creds = awsSTScreate(myAccessKey, mySecretKey, serverRegion, role)

echo creds.AWS_ACCESS_KEY_ID
echo creds.AWS_SECRET_ACCESS_KEY
echo creds.AWS_SESSION_TOKEN
```

Auto-renew and keep credentials in global variable. Accessible from all threads.

```nim
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




# Changelog

## v1.0.4

Replacing dependency `sigv4` with `awsSigV4`. The allows us to ignore the
dependency `balls`.

`awsCredsMonitor()` has been removed.





