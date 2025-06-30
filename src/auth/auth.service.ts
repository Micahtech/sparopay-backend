// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Subscriber } from './subscriber.entity';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dto/login.dto';
import { createHash } from 'crypto';

function md5Hash(input: string): string {
  return createHash('md5').update(input).digest('hex');
}
@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(Subscriber)
    private readonly subscriberRepo: Repository<Subscriber>,
    private readonly jwtService: JwtService
  ) {}
async login(dto: LoginDto) {
  const user = await this.subscriberRepo.findOne({
    where: { phone: dto.sPhone },
  });

  if (!user) {
    throw new UnauthorizedException('Invalid credentials');
  }

  // Hash the input password using MD5 to compare with stored hash
  const hashedInput = md5Hash(dto.sPass);

  if (user.spass !== hashedInput) {
    throw new UnauthorizedException('Invalid credentials');
  }

  const payload = {
    sub: user.id,
    phone: user.phone,
    type: user.type,
  };

  const token = this.jwtService.sign(payload);

  return {
    message: 'Login successful',
    token,
    user,
  };
}
}