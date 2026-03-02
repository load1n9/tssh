export type LogLevel = "debug" | "info" | "warn" | "error";

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export class Logger {
  #levelValue: number;
  #prefix: string;

  constructor(prefix: string, level: LogLevel = "info") {
    this.#prefix = prefix;
    this.#levelValue = LOG_LEVELS[level];
  }

  debug(msg: string, ...args: unknown[]): void {
    if (this.#levelValue <= LOG_LEVELS.debug) {
      console.debug(`[${this.#prefix}] ${msg}`, ...args);
    }
  }

  info(msg: string, ...args: unknown[]): void {
    if (this.#levelValue <= LOG_LEVELS.info) {
      console.info(`[${this.#prefix}] ${msg}`, ...args);
    }
  }

  warn(msg: string, ...args: unknown[]): void {
    if (this.#levelValue <= LOG_LEVELS.warn) {
      console.warn(`[${this.#prefix}] ${msg}`, ...args);
    }
  }

  error(msg: string, ...args: unknown[]): void {
    if (this.#levelValue <= LOG_LEVELS.error) {
      console.error(`[${this.#prefix}] ${msg}`, ...args);
    }
  }

  child(subPrefix: string): Logger {
    return new Logger(`${this.#prefix}:${subPrefix}`, this.level);
  }

  get level(): LogLevel {
    for (const [name, val] of Object.entries(LOG_LEVELS)) {
      if (val === this.#levelValue) return name as LogLevel;
    }
    return "info";
  }

  setLevel(level: LogLevel): void {
    this.#levelValue = LOG_LEVELS[level];
  }
}
