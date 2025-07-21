import {
  WebSocketGateway,
  WebSocketServer,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';
import { Injectable } from '@nestjs/common';

@Injectable()
@WebSocketGateway({ cors: { origin: '*' } })
export class AuthGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() server: Server;

  private socketMap = new Map<number, string>(); // userId -> socket.id

  constructor(private configService: ConfigService) {}

  async handleConnection(socket: Socket) {
    const token = socket.handshake.auth?.token;
    if (!token) return socket.disconnect();

    try {
const jwtSecret = this.configService.getOrThrow<string>('JWT_SECRET');
const payload = jwt.verify(token, jwtSecret) as any;
      const userId = payload.sub;

      // Disconnect old socket if it exists
      const oldSocketId = this.socketMap.get(userId);
      if (oldSocketId && oldSocketId !== socket.id) {
        this.server.to(oldSocketId).emit('force-logout');
        this.server.sockets.sockets.get(oldSocketId)?.disconnect();
      }

      this.socketMap.set(userId, socket.id);
      socket.join(`user-${userId}`);
      socket.data.userId = userId;
    } catch (err) {
      socket.disconnect();
    }
  }

  handleDisconnect(socket: Socket) {
    const userId = socket.data?.userId;
    if (userId) {
      this.socketMap.delete(userId);
    }
  }

  forceLogout(userId: number) {
    const socketId = this.socketMap.get(userId);
    if (socketId) {
      this.server.to(socketId).emit('force-logout');
      this.server.sockets.sockets.get(socketId)?.disconnect();
      this.socketMap.delete(userId);
    }
  }
}
