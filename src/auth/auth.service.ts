// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Subscriber } from '../subscribers/subscriber.entity';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(Subscriber)
    private readonly subscriberRepo: Repository<Subscriber>,
    private jwtService: JwtService,
  ) {}

  async login(phone: string, password: string) {
    const user = await this.subscriberRepo.findOneBy({ phone });

    if (!user || user.password !== password) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = { id: user.id, role: user.role, phone: user.phone };
    const token = this.jwtService.sign(payload);

    return { token, user };
  }
}
