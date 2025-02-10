##
## AWS Security Token Service (AWS STS) is a web service that enables you to
## request temporary, limited-privilege credentials for AWS Identity and Access
## Management (IAM) users or for users that you authenticate (federated users).
## This package is purely for generating ASIAxxxx credentials, which can be used
## in other services.
##

import
  std/[
    json,
    httpcore,
    httpclient,
    parsexml,
    streams,
    strutils,
    times,
    uri
  ]

import
  awsSigV4


type
  AwsCreds* = ref object
    AWS_REGION*: string
    AWS_ACCESS_KEY_ID*: string
    AWS_SECRET_ACCESS_KEY*: string
    AWS_SESSION_TOKEN*: string
    AWS_SESSION_EXPIRE*: int64
    success*: bool


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


proc awsSTScreateASIA(
    awsAccessKey, awsSecretKey, serverRegion, roleArn: string,
    duration = (when defined(dev): 900 else: 3600),
    roleSessionPrefix = (when defined(dev): "asia-dev-" else: "asia-release-")
  ): AwsCreds =
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
    datetime  = makeDateTime()

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
      ("X-Amz-Date", datetime),
    ])

  # sigv4 magic
  let
    scope     = credentialScope(region=region, service=service, date=datetime)
    request   = canonicalRequest(HttpGet, url, query, headers, payload, digest=digest)
    sts       = stringToSign(request, scope, date=datetime, digest=digest)
    signature = calculateSignature(secret=secret, date=datetime, region=region,
                                  service=service, tosign=sts, digest=digest)

  # Update headers with signature
  headers.add("Authorization", $SHA256 & " Credential=" & accessKey & "/" & scope & ", SignedHeaders=content-type;host;x-amz-date, Signature=" & signature)

  # GET data
  let
    client = newHttpClient(headers = headers)

  var
    response: Response

  try:
    response    = client.get(finalUrl)
  finally:
    client.close()

  if not response.code.is2xx:
    echo("awsCredsCreateASIA(): Failed on 200: " & response.body)
    return AwsCreds(
      AWS_REGION:             "",
      AWS_ACCESS_KEY_ID:      "",
      AWS_SECRET_ACCESS_KEY:  "",
      AWS_SESSION_TOKEN:      "",
      AWS_SESSION_EXPIRE:     0,
      success:                false
    )

  when defined(verboseSTS):
    echo(response.body)

  let
    xmlresponse = awsParseXml(response.body)

  return AwsCreds(
    AWS_REGION:             serverRegion,
    AWS_ACCESS_KEY_ID:      xmlresponse[0],
    AWS_SECRET_ACCESS_KEY:  xmlresponse[1],
    AWS_SESSION_TOKEN:      xmlresponse[2],
    AWS_SESSION_EXPIRE:     (parseTime(xmlresponse[3], "yyyy-MM-dd'T'HH:mm:ss'Z'", utc()).toUnix()),
    success:                true
  )


proc awsSTSisExpired*(
    awsCreds: AwsCreds,
    slag = 0
  ): bool =
  ## Checks if the credentials is expired or does not exists.

  if awsCreds.AWS_SESSION_EXPIRE == 0:
    when defined(verboseSTS) or defined(testThreads):
      echo "awsCredsIsExpired(): No value"
    return true

  # In `dev` only subtract 100 seconds.
  if awsCreds.AWS_SESSION_EXPIRE <= toInt(epochTime()) + slag:
    when defined(verboseSTS) or defined(testThreads):
      echo "awsCredsIsExpired(): Is expired (" & $awsCreds.AWS_SESSION_EXPIRE & ")"
    return true

  return false


proc awsSTScreate*(
    awsAccessKey, awsSecretKey, serverRegion, roleArn: string,
    duration = (when defined(dev): 900 else: 3600)
  ): AwsCreds =
  ## Returns the credentials.

  return awsSTScreateASIA(awsAccessKey, awsSecretKey, serverRegion, roleArn, duration)


