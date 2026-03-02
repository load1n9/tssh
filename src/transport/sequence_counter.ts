export class SequenceCounter {
  #value = 0;

  next(): number {
    const v = this.#value;
    this.#value = (this.#value + 1) >>> 0; // uint32 wrap
    return v;
  }

  current(): number {
    return this.#value;
  }
}
