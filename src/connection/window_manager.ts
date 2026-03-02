// deno-lint-ignore-file require-await
import { DEFAULT_WINDOW_SIZE } from "../protocol/constants.ts";

export class WindowManager {
  #window: number;
  #consumed = 0;
  #waiters: Array<{ needed: number; resolve: () => void }> = [];
  #initialSize: number;
  constructor(
    initialSize: number = DEFAULT_WINDOW_SIZE,
    public readonly maxPacketSize: number = 32768,
  ) {
    this.#initialSize = initialSize;
    this.#window = initialSize;
  }

  get available(): number {
    return this.#window;
  }

  consume(bytes: number): void {
    this.#window -= bytes;
    this.#consumed += bytes;
  }

  adjust(bytes: number): void {
    this.#window += bytes;
    // Wake up any waiters that now have enough window
    const satisfied: number[] = [];
    for (let i = 0; i < this.#waiters.length; i++) {
      if (this.#window >= this.#waiters[i].needed) {
        this.#waiters[i].resolve();
        satisfied.push(i);
      }
    }
    // Remove satisfied waiters in reverse order
    for (let i = satisfied.length - 1; i >= 0; i--) {
      this.#waiters.splice(satisfied[i], 1);
    }
  }

  async waitForWindow(needed: number): Promise<void> {
    if (this.#window >= needed) return;
    return new Promise((resolve) => {
      this.#waiters.push({ needed, resolve });
    });
  }

  /** Returns the number of bytes consumed since last reset, for auto-adjust logic */
  getConsumedAndReset(): number {
    const c = this.#consumed;
    this.#consumed = 0;
    return c;
  }

  /** Check if we should send a window adjust (when > 50% consumed) */
  shouldAdjust(): boolean {
    return this.#consumed >= this.#initialSize / 2;
  }

  getAdjustAmount(): number {
    return this.#consumed;
  }
}
