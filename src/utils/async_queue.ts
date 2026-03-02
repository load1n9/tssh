export class AsyncQueue<T> {
  #queue: T[] = [];
  #waiters: Array<{
    resolve: (value: T | undefined) => void;
    reject: (err: Error) => void;
  }> = [];
  #closed = false;
  #error: Error | null = null;

  push(item: T): void {
    if (this.#closed) throw new Error("Queue is closed");
    if (this.#waiters.length > 0) {
      const waiter = this.#waiters.shift()!;
      waiter.resolve(item);
    } else {
      this.#queue.push(item);
    }
  }

  // deno-lint-ignore require-await
  async pop(): Promise<T | undefined> {
    if (this.#queue.length > 0) {
      return this.#queue.shift()!;
    }
    if (this.#closed) {
      if (this.#error) throw this.#error;
      return undefined;
    }
    return new Promise<T | undefined>((resolve, reject) => {
      this.#waiters.push({ resolve, reject });
    });
  }

  close(error?: Error): void {
    this.#closed = true;
    this.#error = error ?? null;
    for (const waiter of this.#waiters) {
      if (error) {
        waiter.reject(error);
      } else {
        waiter.resolve(undefined);
      }
    }
    this.#waiters = [];
  }

  get isClosed(): boolean {
    return this.#closed;
  }

  get length(): number {
    return this.#queue.length;
  }

  async *[Symbol.asyncIterator](): AsyncIterableIterator<T> {
    while (true) {
      const item = await this.pop();
      if (item === undefined) return;
      yield item;
    }
  }
}
