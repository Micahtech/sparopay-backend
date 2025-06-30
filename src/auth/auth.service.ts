// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Subscriber } from './subscriber.entity';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt'; // if passwords are hashed

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(Subscriber)
    private readonly subscriberRepo: Repository<Subscriber>,
    private readonly jwtService: JwtService
  ) {}

  async login(dto: LoginDto) {
  const user = await this.subscriberRepo.findOne({
    where: { phone: dto.sPhone }, // fixed variable name
  });

  if (!user || user.spass !== dto.sPass) { // fixed password field
    throw new UnauthorizedException('Invalid credentials');
  }

  const payload = {
    sub: user.id,          // alias for sId (make sure this is mapped correctly)
    phone: user.phone,
    type: user.type
  };

  const token = this.jwtService.sign(payload);

  return {
    message: 'Login successful',
    token,
    user,
  };
}
}
