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
      where: { sPhone: dto.sPhone },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid phone number');
    }

    // If password is plain text
    if (user.sPass !== dto.sPass) {
      throw new UnauthorizedException('Invalid password');
    }

    // If password is hashed, use:
    // if (!await bcrypt.compare(dto.sPass, user.sPass)) { throw new UnauthorizedException('Invalid password'); }

    const payload = {
      sub: user.sId,
      sPhone: user.sPhone,
      sType: user.sType,
    };

    const token = this.jwtService.sign(payload);

    return {
      message: 'Login successful',
      token,
      user,
    };
  }
}
