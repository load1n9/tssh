import type { TransportHandler } from "../transport/transport_handler.ts";
import { ChannelManager } from "./channel_manager.ts";
import { GlobalRequestHandler } from "./global_request.ts";

/**
 * Connection-layer handler that ties together channels and global requests.
 * Messages 80-100 are dispatched through ChannelManager and GlobalRequestHandler.
 */
export class ConnectionHandler {
  readonly channelManager: ChannelManager;
  readonly globalRequests: GlobalRequestHandler;

  constructor(transport: TransportHandler) {
    this.channelManager = new ChannelManager(transport);
    this.globalRequests = new GlobalRequestHandler(transport);
  }

  async closeAll(): Promise<void> {
    await this.channelManager.closeAll();
  }
}
