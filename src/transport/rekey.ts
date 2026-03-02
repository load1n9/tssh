export interface RekeyConfig {
  maxBytes?: number; // default 1 GB
  maxPackets?: number; // default 2^28
  maxTimeMs?: number; // default 1 hour
}

const DEFAULT_MAX_BYTES = 1024 * 1024 * 1024; // 1 GB
const DEFAULT_MAX_PACKETS = 1 << 28;
const DEFAULT_MAX_TIME_MS = 60 * 60 * 1000; // 1 hour

export class RekeyPolicy {
  #bytesSent = 0;
  #bytesReceived = 0;
  #packetsSent = 0;
  #packetsReceived = 0;
  #lastRekeyTime: number;
  #maxBytes: number;
  #maxPackets: number;
  #maxTimeMs: number;

  constructor(config?: RekeyConfig) {
    this.#maxBytes = config?.maxBytes ?? DEFAULT_MAX_BYTES;
    this.#maxPackets = config?.maxPackets ?? DEFAULT_MAX_PACKETS;
    this.#maxTimeMs = config?.maxTimeMs ?? DEFAULT_MAX_TIME_MS;
    this.#lastRekeyTime = Date.now();
  }

  recordSent(bytes: number): void {
    this.#bytesSent += bytes;
    this.#packetsSent++;
  }

  recordReceived(bytes: number): void {
    this.#bytesReceived += bytes;
    this.#packetsReceived++;
  }

  shouldRekey(): boolean {
    if (this.#bytesSent + this.#bytesReceived >= this.#maxBytes) return true;
    if (this.#packetsSent + this.#packetsReceived >= this.#maxPackets) {
      return true;
    }
    if (Date.now() - this.#lastRekeyTime >= this.#maxTimeMs) return true;
    return false;
  }

  reset(): void {
    this.#bytesSent = 0;
    this.#bytesReceived = 0;
    this.#packetsSent = 0;
    this.#packetsReceived = 0;
    this.#lastRekeyTime = Date.now();
  }
}
