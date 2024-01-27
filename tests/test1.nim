# This is just an example to get you started. You may wish to put all of your
# tests into a single file, or separate them into multiple `test1`, `test2`
# etc. files (better names are recommended, just make sure the name starts with
# the letter 't').
#
# To run these tests, simply execute `nimble test`.

import
  std/[
    httpclient,
    json,
    strutils,
    uri
  ]

import unittest

import
  awsSigV4


let
  accessKey = "credsAccessKey"
  secretKey = "credsSecretKey"
  roleName = "roleName"
  roleArn  = "arn:aws:iam::123456789012:role/" & roleName
  duration = 65

  region    = "us-east-1"
  urlRaw    = "sts." & region & ".amazonaws.com"
  url       = "https://" & urlRaw & "/"
  service   = "s3"

  httpMethod = HttpGet

  payload   = ""
  digest    = SHA256
  datetime  = "20240127T063953Z" #makeDateTime()

  finalUrl  = url & "?Action=AssumeRole&Version=2011-06-15&RoleArn=$1&RoleSessionName=$2&DurationSeconds=$3".format(encodeUrl(roleArn), encodeUrl(roleName), $duration)

  query = %* {
      "Action": "AssumeRole",
      "DurationSeconds": $duration,
      "RoleArn": roleArn,
      "RoleSessionName": roleName,
      "Version": "2011-06-15",
    }

  headers = newHttpHeaders(@[
      ("Host", urlRaw),
      ("Content-Type", "application/x-www-form-urlencoded; charset=utf-8"),
      ("X-Amz-Date", datetime),
    ])



test "check":

  let
    scope = credentialScope(region=region, service=service, date=datetime)
    request = canonicalRequest(httpMethod, url, query, headers, payload, digest = UnsignedPayload)
    sts = stringToSign(request, scope, date = datetime, digest = digest)
    signature = calculateSignature(secret=secretKey, date = datetime, region = region,
                                  service = service, tosign = sts, digest = digest)

  var head = headers
  head.add("Authorization", $SHA256 & " Credential=" & accessKey & "/" & scope & ", SignedHeaders=content-type;host;x-amz-date, Signature=" & signature)

  check scope == "20240127/us-east-1/s3/aws4_request"

  check request == """GET
/
Action=AssumeRole&DurationSeconds=65&RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2FroleName&RoleSessionName=roleName&Version=2011-06-15
content-type:application/x-www-form-urlencoded; charset=utf-8
host:sts.us-east-1.amazonaws.com
x-amz-date:20240127T063953Z

content-type;host;x-amz-date
UNSIGNED-PAYLOAD"""

  check sts == """AWS4-HMAC-SHA256
20240127T063953Z
20240127/us-east-1/s3/aws4_request
4af3ed998ed45b26991ae7a41872420158146e1d5b99706a90376d124db2968a"""

  check signature == "bc855fa92253295339b977001c61cd91f4956d975e646f1a2b9b254710fdd73a"

  check head["content-type"] == "application/x-www-form-urlencoded; charset=utf-8"
  check head["host"] == "sts.us-east-1.amazonaws.com"
  check head["authorization"] == "AWS4-HMAC-SHA256 Credential=credsAccessKey/20240127/us-east-1/s3/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=bc855fa92253295339b977001c61cd91f4956d975e646f1a2b9b254710fdd73a"
  check head["x-amz-date"] == "20240127T063953Z"

  check finalUrl == "https://sts.us-east-1.amazonaws.com/?Action=AssumeRole&Version=2011-06-15&RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2FroleName&RoleSessionName=roleName&DurationSeconds=65"
