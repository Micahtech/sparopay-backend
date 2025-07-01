import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Subscriber } from './subscriber.entity';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dto/login.dto';
import { createHash } from 'crypto';

function legacyHash(password: string): string {
  const md5 = createHash('md5').update(password).digest('hex');
  const sha1 = createHash('sha1').update(md5).digest('hex');
  return sha1.slice(3, 13); // Mimics: substr(sha1(md5(password)), 3, 10)
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

    const hashedInput = legacyHash(dto.sPass);

    if (user.spass !== hashedInput) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = {
      sub: user.id, // ensure subscriber.entity.ts has this mapped
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

  async verifyPin(pin: number, userId: number) {
  const user = await this.subscriberRepo.findOne({ where: { id: userId } });

  if (!user || user.pin !== pin) {
    throw new UnauthorizedException('Invalid PIN');
  }

  return {
    message: 'PIN verified successfully',
    user: {
      id: user.id,
      phone: user.phone,
      type: user.type,
    },
  };
}
}