# Copyright CxPlanner @ Thomas T. Jarløv (TTJ)
##
## AWS Security Token Service (AWS STS) is a web service that enables you to
## request temporary, limited-privilege credentials for AWS Identity and Access
## Management (IAM) users or for users that you authenticate (federated users).
## This package is purely for generating ASIAxxxx credentials, which can be used
## in other services.
##

import
  std/asyncdispatch,
  std/json,
  std/httpcore,
  std/httpclient,
  std/parsexml,
  std/streams,
  std/strutils,
  std/times,
  std/uri

import
  sigv4


type
  AwsCreds* = ref object
    AWS_REGION*: string
    AWS_ACCESS_KEY_ID*: string
    AWS_SECRET_ACCESS_KEY*: string
    AWS_SESSION_TOKEN*: string
    AWS_SESSION_EXPIRE*: int64


const
  expirationInSec =
      when defined(dev):
        900
      else:
        3600

  roleSessionPrefix =
      when defined(dev):
        "asia-dev-"
      else:
        "asia-release-"

var awsCreds {.threadvar.}: AwsCreds      ## IMPORTANT! The credentials are stored
                                          ## in a global {.threadvar.} variable.
                                          ## It therefor needs to be re-initiated
                                          ## for each thread.
                                          ##
var awsCredsInitiated {.threadvar.}: bool ## This is our checker, when ` == true`,
                                          ## our credentials has been created.
                                          ##


proc awsParseXml(data: string): seq[string] =
  ## Parses the AWS XML response and returns needed values.
  ##
  ## Return:
  ## (xAccessKeyId, xSecretAccessKey, xSessionToken, xExpiration)
  var x: XmlParser
  var s = newStringStream(data)
  var
    xAccessKeyId: string
    xSecretAccessKey: string
    xSessionToken: string
    xExpiration: string

  open(x, s, "filename")
  while true:
    x.next()
    case x.kind
    of xmlElementStart:
      case x.elementName
      of "AccessKeyId":
        x.next()
        while x.kind == xmlCharData:
          xAccessKeyId.add(x.charData)
          x.next()
      of "SecretAccessKey":
        x.next()
        while x.kind == xmlCharData:
          xSecretAccessKey.add(x.charData)
          x.next()
      of "SessionToken":
        x.next()
        while x.kind == xmlCharData:
          xSessionToken.add(x.charData)
          x.next()
      of "Expiration":
        x.next()
        while x.kind == xmlCharData:
          xExpiration.add(x.charData)
          x.next()
    of xmlEof: break
    else: discard
  x.close()
  return @[xAccessKeyId, xSecretAccessKey, xSessionToken, xExpiration]


proc awsCredsCreateASIA(awsAccessKey, awsSecretKey, roleArn, serverRegion: string, duration=expirationInSec) =
  ## Creates new ASIA credentials

  let
    urlRaw    = "sts." & serverRegion & ".amazonaws.com"
    url       = "https://" & urlRaw & "/"

    accessKey = awsAccessKey
    secret    = awsSecretKey

    payload   = ""
    region    = serverRegion
    service   = "sts"
    digest    = SHA256
    date      = makeDateTime()

    roleName  = roleSessionPrefix & $toInt(epochTime())

    finalUrl  = url & "?Action=AssumeRole&Version=2011-06-15&RoleArn=$1&RoleSessionName=$2&DurationSeconds=$3".format(encodeUrl(roleArn), encodeUrl(roleName), $duration)

    query = %* {
      "Action": "AssumeRole",
      "DurationSeconds": $duration,
      "RoleArn": roleArn,
      "RoleSessionName": roleName,
      "Version": "2011-06-15",
    }

  var headers = newHttpHeaders(@[
      ("Host", urlRaw),
      ("Content-Type", "application/x-www-form-urlencoded; charset=utf-8"),
      ("X-Amz-Date", date),
    ])

  # sigv4 magic
  let
    scope     = credentialScope(region=region, service=service, date=date)
    request   = canonicalRequest(HttpGet, url, query, headers, payload, digest=digest)
    sts       = stringToSign(request.hash(digest), scope, date=date, digest=digest)
    signature = calculateSignature(secret=secret, date=date, region=region,
                                  service=service, tosign=sts, digest=digest)

  # Update headers with signature
  headers.add("Authorization", $SHA256 & " Credential=" & accessKey & "/" & scope & ", SignedHeaders=content-type;host;x-amz-date, Signature=" & signature)

  # GET data
  let
    client      = newHttpClient(headers = headers)
    response    = client.get(finalUrl)

  if not response.code.is2xx:
    echo("awsCredsCreateASIA(): Failed on 200: " & response.body)
    awsCreds = AwsCreds(
      AWS_REGION:             "",
      AWS_ACCESS_KEY_ID:      "",
      AWS_SECRET_ACCESS_KEY:  "",
      AWS_SESSION_TOKEN:      "",
      AWS_SESSION_EXPIRE:     0
    )
    return

  when defined(dev):
    echo(response.body)

  let
    xmlresponse = awsParseXml(response.body)

  # Save credentials in global {.threadvar.}
  awsCreds = AwsCreds(
    AWS_REGION:             serverRegion,
    AWS_ACCESS_KEY_ID:      xmlresponse[0],
    AWS_SECRET_ACCESS_KEY:  xmlresponse[1],
    AWS_SESSION_TOKEN:      xmlresponse[2],
    AWS_SESSION_EXPIRE:     (parseTime(xmlresponse[3], "yyyy-MM-dd'T'HH:mm:ss'Z'", utc()).toUnix())
  )
  awsCredsInitiated = true


proc awsCredsIsExpired(): bool =
  ## Checks if the credentials is expired or does not exists.

  if awsCreds.AWS_SESSION_EXPIRE == 0:
    when defined(dev): echo "awsCredsIsExpired(): No value"
    return true

  # Subtract 600 seconds (10 minutes)  (release) from current time as a buffer.
  # In `dev` only subtract 100 seconds.
  if awsCreds.AWS_SESSION_EXPIRE < toInt(epochTime() + (when defined(release): 600 else: 100)):
    when defined(dev): echo "awsCredsIsExpired(): Is expired (" & $awsCreds.AWS_SESSION_EXPIRE & ")"
    return true

  return false


proc awsCredsMonitor*(awsAccessKey, awsSecretKey, roleArn, serverRegion: string, duration=expirationInSec) {.async.} =
  ## Monitior the expiration and regenerate before it's too late.
  ##
  ## There are pros and cons:
  ## If you don't activate the monitor, then when the
  ## credentials are expired and you need them you need to wait for
  ## new credentials.
  ## If you activated it you'll get many more calls to AWS STS even though you
  ## might not need it.
  ##
  ## You can activate the monitor at anytime.

  while true:
    await sleepAsync((expirationInSec - (when defined(release): 600 else: 100)) * 1000)

    when defined(dev): echo "awsCredsMonitor(): Time - generating new"
    awsCredsCreateASIA(awsAccessKey, awsSecretKey, roleArn, serverRegion, duration)


proc awsCredentialGet*(awsAccessKey, awsSecretKey, roleArn, serverRegion: string, duration=expirationInSec, autoRenew=false): AwsCreds =
  ## Returns the credentials.
  ##
  ## Since our credentials are stored in a global `{.threadvar.}` this procedure
  ## needs to be called for each thread. Are you running single-threaded then
  ## no worries.

  if not awsCredsInitiated:
    awsCredsCreateASIA(awsAccessKey, awsSecretKey, roleArn, serverRegion, duration)
    # Enable autorenew
    if autoRenew:
      asyncCheck awsCredsMonitor(awsAccessKey, awsSecretKey, roleArn, serverRegion, duration)

  if awsCredsIsExpired():
    awsCredsCreateASIA(awsAccessKey, awsSecretKey, roleArn, serverRegion, duration)

  return awsCreds