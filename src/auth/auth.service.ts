import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Subscriber } from './subscriber.entity';
import { JwtService } from '@nestjs/jwt';
import { MailerService } from '@nestjs-modules/mailer';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { createHash } from 'crypto';

function legacyHash(password: string): string {
  const md5 = createHash('md5').update(password).digest('hex');
  const sha1 = createHash('sha1').update(md5).digest('hex');
  return sha1.slice(3, 13);
}

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(Subscriber)
    private readonly subscriberRepo: Repository<Subscriber>,
    private readonly jwtService: JwtService,
    private readonly mailer: MailerService
  ) {}

  async login(dto: LoginDto) {
    const user = await this.subscriberRepo.findOne({ where: { phone: dto.sPhone } });

    if (!user || !dto.sPass) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const hashedInput = legacyHash(dto.sPass);
    if (user.spass !== hashedInput) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = {
      userId: user.id,
      phone: user.phone,
      type: user.type,
    };

    const token = this.jwtService.sign(payload);
    return { message: 'Login successful', token, user };
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

  async register(dto: RegisterDto) {
    const { email, phone, password, transpin, fname, lname } = dto;

    const existing = await this.subscriberRepo.findOneBy([{ phone }, { email }]);
    if (existing) {
      throw new BadRequestException('Email or phone already in use');
    }

    const hashedPass = legacyHash(password);
    const verCode = Math.floor(1000 + Math.random() * 9000);
    const apiKey = [...Array(60)].map(() => Math.random().toString(36)[2]).join('') + Date.now();

    const newUser = this.subscriberRepo.create({
      fname,
      lname,
      email,
      phone,
      spass: hashedPass,
      pin: parseInt(transpin, 10),
      pinStatus: 0,
      type: 1,
      apiKey,
      verCode,
      regStatus: 0,
      regDate: new Date(),
      wallet: 0.0,
      refWallet: 0.0,
      emailSent: false,
    });

    await this.subscriberRepo.save(newUser);

    await this.mailer.sendMail({
      to: email,
      subject: 'Verify your email - Sparopay',
      text: `Hi ${fname}, use this code to verify your email: ${verCode}`,
    });

    return { message: 'Registration successful. Check your email for the verification code.' };
  }
}
