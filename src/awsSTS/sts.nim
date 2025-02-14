
import
  std/[
    exitprocs,
    locks
  ]

import ../awsSTS
export AwsCreds

import ./pool
export awsSTSInitHttpPool

var lock: Lock
initLock(lock)

var stsKey = AwsCreds(
    AWS_REGION:             "",
    AWS_ACCESS_KEY_ID:      "",
    AWS_SECRET_ACCESS_KEY:  "",
    AWS_SESSION_TOKEN:      "",
    AWS_SESSION_EXPIRE:     0,
    success:                false
  )


proc stsGet*(
    awsAccessKey, awsSecretKey, serverRegion, roleArn: string,
    duration = (when defined(dev): 900 else: 3600)
  ): AwsCreds {.gcsafe.} =

  acquire(lock)

  {.locks: [lock], gcsafe.}:
    result = stsKey

    if awsSTSisExpired(stsKey):
      when defined(verboseSTS) or defined(testThreads):
        echo "STS expired, renewing..."

      stsKey =
        awsSTScreateASIA(
          awsAccessKey, awsSecretKey,
          serverRegion, roleArn,
          duration = duration
        )
      result = stsKey

  release(lock)

  return result


proc cleanup() =
  if stsKey != nil:
    `=destroy`(stsKey)

addExitProc(proc() =
    cleanup()
  )