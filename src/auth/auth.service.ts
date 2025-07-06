import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  Logger,
  Req,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Subscriber } from './subscriber.entity';
import { JwtService } from '@nestjs/jwt';
import { MailerService } from '@nestjs-modules/mailer';
import {
  RegisterDto, LoginDto, VerifyEmailDto, ResendVerificationDto,
  VerifyPinDto, CreatePinWithAuthDto, ForgotPasswordDto, ResetPasswordDto,
  ForgotPinDto, ResetPinDto, ResetPasswordAuthDto,
} from './dto';
import { createHash, randomBytes } from 'crypto';
import Redis from 'ioredis';
import { Request } from 'express';
import * as geoip from 'geoip-lite';
import * as UAParser from 'ua-parser-js';


if (!process.env.REDIS_URL) throw new Error('REDIS_URL is not defined');
const redis = new Redis(process.env.REDIS_URL);
const logger = new Logger('AuthService');

function legacyHash(password: string): string {
  const md5 = createHash('md5').update(password).digest('hex');
  const sha1 = createHash('sha1').update(md5).digest('hex');
  return sha1.slice(3, 13);
}

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(Subscriber)
    private readonly subRepo: Repository<Subscriber>,
    private readonly jwtService: JwtService,
    private readonly mailer: MailerService,
  ) {}

  private async blacklistPreviousToken(userId: number) {
    const key = `userToken:${userId}`;
    const current = await redis.get(key);
    if (current) {
      await redis.set(`blacklist:${current}`, 'true', 'EX', 60 * 60 * 24);
    }
  }

  private clean(user: Subscriber) {
    const { spass, verCode, verCodeType, pin, ...rest } = user;
    return rest;
  }

  async register(dto: RegisterDto) {
    const exists = await this.subRepo.findOne({
      where: [{ email: dto.email }, { phone: dto.phone }],
    });
    if (exists) throw new BadRequestException('Email or phone already exists');

    const user = this.subRepo.create({
      ...dto,
      spass: legacyHash(dto.password),
      verCode: Math.floor(1000 + Math.random() * 9000),
      verCodeType: 'email_verification',
      regStatus: 0,
    });

    await this.subRepo.save(user);
    await this.mailer.sendMail({
      to: dto.email,
      subject: 'Verify your email',
      text: `Your verification code is ${user.verCode}`,
    });

    return { message: 'Registered. Check your email to verify your account.' };
  }

  async verifyEmail(dto: VerifyEmailDto) {
    const user = await this.subRepo.findOne({ where: { email: dto.email } });
    if (!user) throw new BadRequestException('Email not found');
    if (user.regStatus >= 1) return { message: 'Already verified.' };
    if (user.verCode !== dto.code || user.verCodeType !== 'email_verification')
      throw new UnauthorizedException('Invalid code');

    user.regStatus = 2;
    user.verCode = null;
    user.verCodeType = null;
    await this.subRepo.save(user);
    return { message: 'Email verified successfully.' };
  }

  async resendVerificationCode(dto: ResendVerificationDto) {
    const user = await this.subRepo.findOne({ where: { email: dto.email } });
    if (!user) throw new BadRequestException('Email not found');
    if (user.regStatus >= 1) return { message: 'Already verified.' };

    user.verCode = Math.floor(1000 + Math.random() * 9000);
    user.verCodeType = 'email_verification';
    await this.subRepo.save(user);
    await this.mailer.sendMail({
      to: user.email,
      subject: 'New Verification Code',
      text: `Your new verification code is ${user.verCode}`,
    });

    return { message: 'Verification code resent.' };
  }
  async createPin(dto: CreatePinWithAuthDto) {
  const u = await this.subRepo.findOne({ where: { phone: dto.phone } });
  if (!u) throw new BadRequestException('User not found');
  if (legacyHash(dto.password) !== u.spass) throw new UnauthorizedException('Wrong password');
  if (u.regStatus < 2) throw new UnauthorizedException('Email not verified');
  if (!/^\d{4}$/.test(dto.pin)) throw new BadRequestException('PIN must be 4 digits');

  u.pin = parseInt(dto.pin, 10);
  u.pinStatus = 1;
  u.regStatus = 1; // ✅ Ensure user can now log in
  await this.subRepo.save(u);

  return { message: 'PIN created successfully.' };
}


  async login(dto: LoginDto, req: Request) {
    const user = await this.subRepo.findOne({ where: { phone: dto.sPhone } });
    if (!user || legacyHash(dto.sPass) !== user.spass)
      throw new UnauthorizedException('Invalid credentials');
    if (user.regStatus === 0) return { message: 'Verify your email.' };
    if (user.regStatus === 2) return { message: 'Set your PIN.' };

    // Blacklist old token
    await this.blacklistPreviousToken(user.id);

    const token = this.jwtService.sign({ sub: user.id, phone: user.phone, type: user.type });
    await redis.set(`userToken:${user.id}`, token, 'EX', 60 * 60 * 24);

    // Send login alert
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const geo = geoip.lookup(ip?.toString() || '');
    const parser = new UAParser.UAParser();
parser.setUA(req.headers['user-agent'] ?? '');
const ua = parser.getResult();


    await this.mailer.sendMail({
      to: user.email,
      subject: 'New Login Detected',
      text: `New login to your account\nIP: ${ip}\nLocation: ${geo?.city || 'Unknown'}, ${geo?.country || 'N/A'}\nDevice: ${ua.device?.model || 'N/A'} (${ua.os.name} ${ua.os.version})\nTime: ${new Date().toLocaleString()}`
    });

    return { message: `Welcome, ${user.fname}`, token, user: this.clean(user) };
  }
  async verifyPin(dto: VerifyPinDto, userId: number) {
  const user = await this.subRepo.findOne({ where: { id: userId } });
  const pin = parseInt(dto.pin.toString(), 10); // Normalize input
  if (!user || user.pin !== pin) throw new UnauthorizedException('Invalid PIN');
  return { message: 'PIN verified.' };
}

  async forgotPassword(dto: ForgotPasswordDto) {
    const user = await this.subRepo.findOne({ where: { email: dto.email } });
    if (!user) throw new BadRequestException('Email not found');

    user.verCode = Math.floor(1000 + Math.random() * 9000);
    user.verCodeType = 'password_reset';
    await this.subRepo.save(user);
    await this.mailer.sendMail({
      to: user.email,
      subject: 'Reset Password Code',
      text: `Code: ${user.verCode}`,
    });

    return { message: 'Reset code sent.' };
  }

  async resetPassword(dto: ResetPasswordDto) {
    const user = await this.subRepo.findOne({ where: { email: dto.email } });
    if (!user) throw new BadRequestException('Email not found');
    if (user.verCode !== dto.code || user.verCodeType !== 'password_reset')
      throw new UnauthorizedException('Invalid code');

    user.spass = legacyHash(dto.newPassword);
    user.verCode = null;
    user.verCodeType = null;
    await this.subRepo.save(user);
    return { message: 'Password updated.' };
  }

  async forgotPin(userId: number, dto: ForgotPinDto) {
    const user = await this.subRepo.findOne({ where: { id: userId } });
    if (!user || legacyHash(dto.password) !== user.spass)
      throw new UnauthorizedException('Invalid password');
    if (user.verCode !== dto.code || user.verCodeType !== 'pin_reset')
      throw new UnauthorizedException('Invalid code');

    user.pin = parseInt(dto.newPin, 10);
    user.verCode = null;
    user.verCodeType = null;
    await this.subRepo.save(user);
    return { message: 'PIN reset.' };
  }

  async resetPin(userId: number, dto: ResetPinDto) {
    const user = await this.subRepo.findOne({ where: { id: userId } });
    if (!user || user.pin !== parseInt(dto.oldPin, 10))
      throw new UnauthorizedException('Wrong old PIN');

    user.pin = parseInt(dto.newPin, 10);
    await this.subRepo.save(user);
    return { message: 'PIN changed.' };
  }

  async resetPasswordAuth(userId: number, dto: ResetPasswordAuthDto) {
    const user = await this.subRepo.findOne({ where: { id: userId } });
    if (!user || legacyHash(dto.oldPassword) !== user.spass)
      throw new UnauthorizedException('Wrong old password');

    user.spass = legacyHash(dto.newPassword);
    await this.subRepo.save(user);
    return { message: 'Password changed.' };
  }

  async logout(userId: number, token: string) {
    await redis.set(`blacklist:${token}`, 'true', 'EX', 60 * 60 * 24);
    await redis.del(`userToken:${userId}`);
    return { message: 'Logged out successfully.' };
  }
}
