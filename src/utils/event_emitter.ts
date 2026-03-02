// deno-lint-ignore-file no-explicit-any
export type EventHandler<T = unknown> = (data: T) => void | Promise<void>;

export class TypedEventEmitter<
  T extends Record<string, any> = Record<string, any>,
> {
  #handlers = new Map<keyof T, Set<EventHandler<unknown>>>();

  on<K extends keyof T>(event: K, handler: EventHandler<T[K]>): this {
    let set = this.#handlers.get(event);
    if (!set) {
      set = new Set();
      this.#handlers.set(event, set);
    }
    set.add(handler as EventHandler<unknown>);
    return this;
  }

  once<K extends keyof T>(event: K): Promise<T[K]> {
    return new Promise((resolve) => {
      const handler: EventHandler<T[K]> = (data) => {
        this.off(event, handler);
        resolve(data);
      };
      this.on(event, handler);
    });
  }

  off<K extends keyof T>(event: K, handler: EventHandler<T[K]>): this {
    const set = this.#handlers.get(event);
    if (set) {
      set.delete(handler as EventHandler<unknown>);
      if (set.size === 0) this.#handlers.delete(event);
    }
    return this;
  }

  emit<K extends keyof T>(event: K, data: T[K]): void {
    const set = this.#handlers.get(event);
    if (set) {
      for (const handler of set) {
        try {
          handler(data);
        } catch (_) {
          // Swallow sync errors from #handlers
        }
      }
    }
  }

  removeAllListeners(event?: keyof T): this {
    if (event !== undefined) {
      this.#handlers.delete(event);
    } else {
      this.#handlers.clear();
    }
    return this;
  }

  listenerCount(event: keyof T): number {
    return this.#handlers.get(event)?.size ?? 0;
  }
}
