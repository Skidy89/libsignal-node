// vim: ts=4:sw=4:expandtab

/*
 * jobQueue manages multiple queues indexed by device to serialize
 * session io ops on the database.
 */
"use strict";

const _queueAsyncBuckets = new Map();
const _jobTimeout = 30000;

/*
 * Reject the caller when an operation takes too long. The operation is
 * still awaited by the queue so a timed-out job cannot overlap the next one.
 */
function withTimeout(operation, ms) {
  let timer;
  const timeout = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error("Job timed out")), ms);
  });
  return Promise.race([operation, timeout]).finally(() => clearTimeout(timer));
}

module.exports = function (bucket, awaitable) {
  /* Run the async awaitable only when all other async calls registered
   * here have completed (or thrown).  The bucket argument is a hashable
   * key representing the task queue to use. */
  if (typeof awaitable !== "function") {
    throw new TypeError("awaitable must be a function");
  }

  const previous = _queueAsyncBuckets.get(bucket) || Promise.resolve();
  const operation = previous
    .catch(() => undefined)
    .then(() => Promise.resolve().then(awaitable));
  const job = withTimeout(operation, _jobTimeout);
  _queueAsyncBuckets.set(bucket, operation);

  operation.then(
    () => {
      if (_queueAsyncBuckets.get(bucket) === operation) {
        _queueAsyncBuckets.delete(bucket);
      }
    },
    () => {
      if (_queueAsyncBuckets.get(bucket) === operation) {
        _queueAsyncBuckets.delete(bucket);
      }
    },
  );

  return job;
};
