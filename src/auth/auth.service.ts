import {
  Injectable, BadRequestException, UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Subscriber } from './subscriber.entity';
import { JwtService } from '@nestjs/jwt';
import { MailerService } from '@nestjs-modules/mailer';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ResendVerificationDto } from './dto/resend-verification.dto';
import { VerifyPinDto } from './dto/verify-pin.dto';
import { CreatePinDto } from './dto/create-pin.dto';
import { createHash, randomBytes } from 'crypto';

function legacyHash(password: string): string {
  const md5 = createHash('md5').update(password).digest('hex');
  const sha1 = createHash('sha1').update(md5).digest('hex');
  return sha1.slice(3, 13);
}

function generateApiKey(): string {
  return randomBytes(16).toString('hex');
}

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(Subscriber)
    private readonly subRepo: Repository<Subscriber>,
    private readonly jwtService: JwtService,
    private readonly mailer: MailerService,
  ) {}

  async register(dto: RegisterDto) {
    const exists = await this.subRepo.findOne({
      where: [{ email: dto.email }, { phone: dto.phone }],
    });
    if (exists) throw new BadRequestException('Email or phone already exists');

    const hash = legacyHash(dto.password);
    const code = Math.floor(1000 + Math.random() * 9000);

    const sub = this.subRepo.create({
      apiKey: generateApiKey(),
      fname: dto.fname,
      lname: dto.lname,
      email: dto.email,
      phone: dto.phone,
      spass: hash,
      state: dto.state,
      pin: 0,
      pinStatus: 0,
      type: 0,
      wallet: 0,
      refWallet: 0,
      verCode: code,
      regStatus: 0, // unverified
      emailSent: false,
      newPin: '',
    });

    await this.subRepo.save(sub);

    await this.mailer.sendMail({
      to: dto.email,
      subject: 'Verify your email',
      text: `Your verification code is ${code}`,
    });

    return { message: 'Registered. Enter code sent to email to verify.' };
  }

  async verifyEmail(dto: VerifyEmailDto) {
    const user = await this.subRepo.findOne({ where: { email: dto.email } });
    if (!user) throw new BadRequestException('Email not found');

    if (user.regStatus === 1 || user.regStatus === 2) {
      return { message: 'Already verified' };
    }

    if (user.verCode !== dto.code) {
      throw new UnauthorizedException('Invalid code');
    }

    user.regStatus = 2; // Email verified but no pin
    await this.subRepo.save(user);

    return { message: 'Email verified successfully' };
  }

  async resendVerificationCode(dto: ResendVerificationDto) {
    const user = await this.subRepo.findOne({ where: { email: dto.email } });
    if (!user) throw new BadRequestException('Email not found');

    if (user.regStatus === 1 || user.regStatus === 2) {
      return { message: 'Already verified' };
    }

    const code = Math.floor(1000 + Math.random() * 9000);
    user.verCode = code;
    await this.subRepo.save(user);

    await this.mailer.sendMail({
      to: dto.email,
      subject: 'New verification code',
      text: `Your new code is ${code}`,
    });

    return { message: 'New code sent to email' };
  }
async createPin(dto: CreatePinDto & { phone: string; password: string }) {
  const user = await this.subRepo.findOne({ where: { phone: dto.phone } });
  if (!user) throw new UnauthorizedException('User not found');

  const hash = legacyHash(dto.password);
  if (user.spass !== hash) throw new UnauthorizedException('Wrong password');

  if (user.regStatus !== 2) {
    throw new UnauthorizedException('You must verify your email before creating a PIN');
  }

  if (dto.pin === '1234') {
    throw new BadRequestException('PIN is too weak');
  }

  user.newPin = dto.pin;
  user.regStatus = 1;
  await this.subRepo.save(user);

  return { message: 'PIN created successfully' };
}

  async login(dto: LoginDto) {
    const user = await this.subRepo.findOne({ where: { phone: dto.sPhone } });
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const hash = legacyHash(dto.sPass);
    if (user.spass !== hash) throw new UnauthorizedException('Invalid credentials');

    if (user.regStatus !== 1) {
      throw new UnauthorizedException('Please complete verification and PIN setup first');
    }

    const payload = { sub: user.id, phone: user.phone, type: user.type };
    const token = this.jwtService.sign(payload);

    return {
      message: 'Login successful',
      pinRequired: false,
      token,
      user,
    };
  }

  async verifyPin(dto: VerifyPinDto, userId: number) {
    const user = await this.subRepo.findOne({ where: { id: userId } });
    if (!user || user.pin !== dto.pin) throw new UnauthorizedException('Invalid PIN');
    return { message: 'PIN verified' };
  }
}
