import
  std/[
    httpclient,
    locks,
    net,
    random,
    times
  ]


type
  PooledClient = object
    client: HttpClient
    lastUsed: Time
    requestCount: int
    consecutiveFailures: int

  HttpClientPool* = ptr HttpClientPoolObj
  HttpClientPoolObj = object
    entries*: seq[PooledClient]
    lock: Lock
    cond: Cond
    r: Rand
    maxAge: Duration
    maxRequests: int
    maxFailures: int

const
  defaultMaxAge = initDuration(minutes = 30)
  defaultMaxRequests = 1000
  defaultMaxFailures = 3

## Global HTTP client pool for AWS STS
var globalPool*: HttpClientPool


proc newHttpClientPool*(size: int): HttpClientPool =
  result = cast[HttpClientPool](allocShared0(sizeof(HttpClientPoolObj)))
  initLock(result.lock)
  initCond(result.cond)
  result.r = initRand(2023)
  result.maxAge = defaultMaxAge
  result.maxRequests = defaultMaxRequests
  result.maxFailures = defaultMaxFailures

  # Initialize pool with clients
  for i in 0..<size:
    result.entries.add(PooledClient(
      client: newHttpClient(),
      lastUsed: getTime(),
      requestCount: 0,
      consecutiveFailures: 0
    ))
    when defined(dev):
      echo "awsSTSInitHttpPool: Initialized HTTP client ", i

  when not defined(awsStsHttpPoolNoEcho):
    echo "awsSTSInitHttpPool: Initialized HTTP client pool with ", size, " clients"


proc shouldRefreshClient(client: PooledClient, pool: HttpClientPool): bool =
  ## Checks if the client should be refreshed based on the pool settings
  let now = getTime()
  result = (now - client.lastUsed > pool.maxAge) or # Age limit
          (client.requestCount >= pool.maxRequests) or # Request limit
          (client.consecutiveFailures >= pool.maxFailures) # Failure limit


proc refreshClient(pool: HttpClientPool, index: int) =
  ## Refreshes the client at the given index
  try:
    pool.entries[index].client.close()
  except:
    discard # Handle cleanup failure

  pool.entries[index] = PooledClient(
    client: newHttpClient(),
    lastUsed: getTime(),
    requestCount: 0,
    consecutiveFailures: 0
  )


proc borrow*(pool: HttpClientPool): HttpClient {.raises: [LibraryError, SslError, HttpRequestError, Exception], gcsafe.} =
  ## Borrows a client from the pool
  acquire(pool.lock)
  while pool.entries.len == 0:
    wait(pool.cond, pool.lock)

  # Find a healthy client or refresh if needed
  var clientIndex = pool.entries.high
  let entry = addr pool.entries[clientIndex]

  if shouldRefreshClient(entry[], pool):
    when defined(dev):
      echo "Refreshing client due to age, requests: ", entry.requestCount, ", failures: ", entry.consecutiveFailures, ", last used: ", entry.lastUsed
    refreshClient(pool, clientIndex)

  result = entry.client
  entry.lastUsed = getTime()
  inc entry.requestCount

  # Remove from available pool
  pool.entries.del(clientIndex)
  release(pool.lock)


proc recycle*(pool: HttpClientPool, client: HttpClient, hadError: bool = false) {.raises: [], gcsafe.} =
  withLock pool.lock:
    for i in 0..<pool.entries.len:
      if pool.entries[i].client == client:
        if hadError:
          inc pool.entries[i].consecutiveFailures
        else:
          pool.entries[i].consecutiveFailures = 0
        break

    # Add back to pool and shuffle
    pool.entries.add(PooledClient(
      client: client,
      lastUsed: getTime(),
      requestCount: 0,
      consecutiveFailures: 0
    ))
    pool.r.shuffle(pool.entries)
  signal(pool.cond)


proc close*(pool: HttpClientPool) {.raises: [].} =
  ## Closes all HTTP clients and deallocates the pool
  withLock pool.lock:
    for entry in pool.entries:
      try:
        entry.client.close()
      except:
        discard

  deinitLock(pool.lock)
  deinitCond(pool.cond)
  `=destroy`(pool[])
  deallocShared(pool)


template ensurePoolInitialized() =
  when not declared(poolInitialized):
    {.error: "You must call awsSTSInitHttpPool() to use this library".}


template withClient*(pool: HttpClientPool, client: untyped, headers: HttpHeaders, body: untyped) =
  if pool == nil:  # Double-check at runtime
    raise newException(ValueError, "HTTP client pool not initialized")

  block:
    var hadError = false
    let client = pool.borrow()
    client.headers = headers
    try:
      body
    except:
      hadError = true
      raise
    finally:
      if client != nil:
        try:
          # Close only the current socket, not the entire client
          let socket = client.getSocket()
          if socket != nil:
            socket.close()
        except:
          discard  # Log error if needed
      pool.recycle(client, hadError)


proc awsSTSInitHttpPool*(size: int = 5) =
  ## Initializes the global HTTP client pool for AWS STS
  if globalPool != nil:
    return  # Already initialized
  try:
    when not defined(awsStsHttpPoolNoEcho):
      echo "awsSTSInitHttpPool: Initializing global HTTP client pool for AWS STS..."
    globalPool = newHttpClientPool(size)
  except:
    raise
