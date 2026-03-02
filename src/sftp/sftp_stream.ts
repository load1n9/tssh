import type { SftpClient } from "./sftp_client.ts";
import type { SftpHandle } from "./sftp_types.ts";

/** Create a ReadableStream for downloading a remote file via SFTP */
export function createSftpReadStream(
  client: SftpClient,
  handle: SftpHandle,
  options?: { offset?: bigint; length?: bigint; chunkSize?: number },
): ReadableStream<Uint8Array> {
  let currentOffset = options?.offset ?? 0n;
  const endOffset = options?.length !== undefined
    ? currentOffset + options.length
    : undefined;
  const chunkSize = options?.chunkSize ?? 32768;

  return new ReadableStream({
    async pull(controller) {
      const readLen = endOffset !== undefined
        ? Math.min(chunkSize, Number(endOffset - currentOffset))
        : chunkSize;

      if (readLen <= 0) {
        controller.close();
        return;
      }

      const data = await client.read(handle, currentOffset, readLen);
      if (data === null) {
        controller.close();
        return;
      }

      controller.enqueue(data);
      currentOffset += BigInt(data.length);
    },
  });
}

/** Create a WritableStream for uploading to a remote file via SFTP */
export function createSftpWriteStream(
  client: SftpClient,
  handle: SftpHandle,
  options?: { offset?: bigint },
): WritableStream<Uint8Array> {
  let currentOffset = options?.offset ?? 0n;

  return new WritableStream({
    async write(chunk) {
      await client.write(handle, currentOffset, chunk);
      currentOffset += BigInt(chunk.length);
    },
  });
}

/** Pipelined download for maximum throughput over high-latency connections */
export async function pipelinedDownload(
  client: SftpClient,
  handle: SftpHandle,
  dest: WritableStream<Uint8Array>,
  options?: {
    fileSize?: bigint;
    chunkSize?: number;
    maxConcurrentRequests?: number;
  },
): Promise<void> {
  const chunkSize = options?.chunkSize ?? 32768;
  const maxConcurrent = options?.maxConcurrentRequests ?? 16;
  const fileSize = options?.fileSize;
  const writer = dest.getWriter();

  let nextReadOffset = 0n;
  let nextWriteOffset = 0n;
  const inflight = new Map<
    string,
    Promise<{ offset: bigint; data: Uint8Array | null }>
  >();
  const completed = new Map<string, Uint8Array | null>();
  let done = false;

  try {
    while (!done) {
      // Fill the pipeline
      while (inflight.size < maxConcurrent && !done) {
        if (fileSize !== undefined && nextReadOffset >= fileSize) break;
        const thisOffset = nextReadOffset;
        const key = thisOffset.toString();
        const promise = client
          .read(handle, thisOffset, chunkSize)
          .then((data) => ({ offset: thisOffset, data }));
        inflight.set(key, promise);
        nextReadOffset += BigInt(chunkSize);
      }

      if (inflight.size === 0) break;

      // Wait for any request to complete
      const result = await Promise.race(inflight.values());
      inflight.delete(result.offset.toString());
      completed.set(result.offset.toString(), result.data);

      // Write completed chunks in order
      while (completed.has(nextWriteOffset.toString())) {
        const key = nextWriteOffset.toString();
        const data = completed.get(key)!;
        completed.delete(key);
        if (data === null) {
          done = true;
          break;
        }
        await writer.write(data);
        nextWriteOffset += BigInt(data.length);
      }
    }

    await writer.close();
  } catch (err) {
    writer.abort(err instanceof Error ? err : new Error(String(err)));
    throw err;
  } finally {
    writer.releaseLock();
  }
}
