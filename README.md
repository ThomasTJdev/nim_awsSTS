# awsSTS

**AWS Security Token Service API in Nim**

This nim package is for generating AWS Security Token Service and temporary
ASIAxxx credentials.

AWS Security Token Service (AWS STS) is a web service that enables you to
request temporary, limited-privilege credentials for AWS Identity and Access
Management (IAM) users or for users that you authenticate (federated users).

This package is purely for generating ASIAxxxx credentials, which can be used
in other services.

If you need more API's then take a look at [atoz](https://github.com/disruptek/atoz).


# Threads

The credentials are stored in a global `{.threadvar.}` when `awsCredentialGet()`
is called. You are responsible for initiating `awsCredentialGet()` in each thread
or you can create a PR to share the credentials among the threads *(waiting for
nim v2.0...)*.



# Example

```nim
let
  myAccessKey   = "AKIDEXAMPLE"
  mySecretKey   = "23456OIUYTREXAMPLE"
  role          = "arn:aws:iam::87654322345:role/Role-I-Can-And-May"
  serverRegion  = "eu-west-1"

let creds = awsCredentialGet(myAccessKey, mySecretKey, role, serverRegion)
#let creds = awsCredentialGet(myAccessKey, mySecretKey, role, serverRegion, autoRenew=true)

echo creds.AWS_ACCESS_KEY_ID
echo creds.AWS_SECRET_ACCESS_KEY
echo creds.AWS_SESSION_TOKEN
```







# Code

## awsCredsMonitor*

```nim
proc awsCredsMonitor*(awsAccessKey, awsSecretKey, roleArn, serverRegion: string, duration=expirationInSec) {.async.} =
```

Monitior the expiration and regenerate before it's too late. 

 There are pros and cons: If you don't activate the monitor, then when the credentials are expired and you need them you (your user) needs to wait for new credentials. If you activated it you'll get many more calls to AWS STS even though you might not need it. 

 You can activate the monitor at anytime.


____

## awsCredentialGet*

```nim
proc awsCredentialGet*(awsAccessKey, awsSecretKey, roleArn, serverRegion: string, duration=expirationInSec, autoRenew=false): AwsCreds =
```

Returns the credentials. 

Since our credentials are stored in a global `{.threadvar.}` this procedure needs to be called for each thread. Are you running single-threaded then no worries.

Setting `autoRenew=true` enables `awsCredsMonitor()`.

____


## AwsCreds* aka credentials

The credentials are returned in type, `AwsCreds`.

```nim
type
  AwsCreds* = ref object
    AWS_REGION*: string
    AWS_ACCESS_KEY_ID*: string
    AWS_SECRET_ACCESS_KEY*: string
    AWS_SESSION_TOKEN*: string
    AWS_SESSION_EXPIRE*: int64
```


# Other

## Duration of credentials

Defaults to:
```nim
const
  expirationInSec =
      when defined(dev):
        900
      else:
        3600
```

## RoleSessionName

The unix-time is appended to identification in your logs.

```nim
const
  roleSessionPrefix =
      when defined(dev):
        "asia-dev-"
      else:
        "asia-release-"
```

_____

**README generated with [nimtomd](https://github.com/ThomasTJdev/nimtomd)**
