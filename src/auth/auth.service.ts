import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Subscriber } from './subscriber.entity';
import { JwtService } from '@nestjs/jwt';
import { MailerService } from '@nestjs-modules/mailer';
import {
  RegisterDto,
  LoginDto,
  VerifyEmailDto,
  ResendVerificationDto,
  VerifyPinDto,
  CreatePinWithAuthDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  ForgotPinDto,
  ResetPinDto,
  ResetPasswordAuthDto,
} from './dto';
import { createHash } from 'crypto';
import Redis from 'ioredis';
import geoip from 'geoip-lite';

if (!process.env.REDIS_URL) throw new Error('REDIS_URL is undefined');
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
      await redis.set(`blacklist:${current}`, 'blacklisted', 'EX', 60 * 60 * 24);
    }
  }

  private clean(user: Subscriber) {
    const { spass, verCode, verCodeType, pin, newPin, ...rest } = user;
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
    return { message: 'Registered successfully. Verify your email.' };
  }

  async verifyEmail(dto: VerifyEmailDto) {
    const u = await this.subRepo.findOne({ where: { email: dto.email } });
    if (!u) throw new BadRequestException('Email not found');
    if (u.regStatus >= 1) return { message: 'Already verified.' };
    if (u.verCode !== dto.code || u.verCodeType !== 'email_verification') {
      throw new UnauthorizedException('Invalid code');
    }
    u.regStatus = 2;
    u.verCode = null;
    u.verCodeType = null;
    await this.subRepo.save(u);
    return { message: 'Email verified success.' };
  }

  async resendVerificationCode(dto: ResendVerificationDto) {
    const u = await this.subRepo.findOne({ where: { email: dto.email } });
    if (!u) throw new BadRequestException('Email not found');
    if (u.regStatus >= 1) return { message: 'Already verified.' };
    u.verCode = Math.floor(1000 + Math.random() * 9000);
    u.verCodeType = 'email_verification';
    await this.subRepo.save(u);
    await this.mailer.sendMail({
      to: dto.email,
      subject: 'Your new verification code',
      text: `Code: ${u.verCode}`,
    });
    return { message: 'Verification code resent.' };
  }

  async createPin(dto: CreatePinWithAuthDto) {
    const u = await this.subRepo.findOne({ where: { phone: dto.phone } });
    if (!u) throw new BadRequestException('User not found');
    if (legacyHash(dto.password) !== u.spass)
      throw new UnauthorizedException('Wrong password');
    if (u.regStatus < 2)
      throw new UnauthorizedException('Email not verified');
    if (!/^\d{4}$/.test(dto.pin))
      throw new BadRequestException('PIN must be 4 digits');
    u.pin = parseInt(dto.pin, 10);
    u.pinStatus = 1;
    await this.subRepo.save(u);
    return { message: 'PIN created successfully.' };
  }

  async login(dto: LoginDto, ip: string, ua: string) {
    const u = await this.subRepo.findOne({ where: { phone: dto.sPhone } });
    if (!u || legacyHash(dto.sPass) !== u.spass)
      throw new UnauthorizedException('Invalid credentials');
    if (u.regStatus === 0) return { message: 'Please verify your email.' };
    if (u.regStatus === 2)
      return { message: 'Email verified. Please set your PIN.' };

    // Enforce single active session
    await this.blacklistPreviousToken(u.id);
    const token = this.jwtService.sign({
      sub: u.id,
      phone: u.phone,
      type: u.type,
    });
    await redis.set(`userToken:${u.id}`, token, 'EX', 60 * 60 * 24);

    // Geo/IP lookup
    const geo = geoip.lookup(ip) || {};
    const city = geo.city || 'Unknown';

    // Notification email
    await this.mailer.sendMail({
      to: u.email,
      subject: 'New Login Notification',
      text: `
Hello ${u.fname},

Your account was accessed on ${new Date().toLocaleString()} from ${city}.
IP: ${ip}
Device: ${ua}

If this wasn't you, please change your password immediately.
      `,
    });

    u.lastActivity = new Date();
    u.lastIP = ip;
    await this.subRepo.save(u);

    return {
      message: `Welcome back, ${u.fname}!`,
      token,
      user: this.clean(u),
      lastLogin: u.lastActivity,
    };
  }

  async verifyPin(dto: VerifyPinDto, userId: number) {
    const u = await this.subRepo.findOne({ where: { id: userId } });
    if (!u || u.pin !== dto.pin)
      throw new UnauthorizedException('Invalid PIN');
    return { message: 'PIN verified.' };
  }

  // forgot/reset password and PIN methods remain unchanged...

  
  
    async forgotPassword(dto: ForgotPasswordDto) {
      const u = await this.subRepo.findOne({ where: { email: dto.email } });
      if (!u) throw new BadRequestException('Email not found');
  
      u.verCode = Math.floor(1000 + Math.random() * 9000);
      u.verCodeType = 'password_reset';
      await this.subRepo.save(u);
      await this.mailer.sendMail({
        to: dto.email,
        subject: 'Password reset code',
        text: `Code: ${u.verCode}`,
      });
      return { message: 'Reset code sent.' };
    }
  
    async resetPassword(dto: ResetPasswordDto) {
      const u = await this.subRepo.findOne({ where: { email: dto.email } });
      if (!u) throw new BadRequestException('Email not found');
      if (u.verCode !== dto.code || u.verCodeType !== 'password_reset')
        throw new UnauthorizedException('Invalid code');
  
      u.spass = legacyHash(dto.newPassword);
      u.verCode = null;
      u.verCodeType = null;
      await this.subRepo.save(u);
      return { message: 'Password updated.' };
    }
  
    async forgotPin(userId: number, dto: ForgotPinDto) {
      const u = await this.subRepo.findOne({ where: { id: userId } });
      if (!u || legacyHash(dto.password) !== u.spass) throw new UnauthorizedException('Invalid password');
      if (u.verCode !== dto.code || u.verCodeType !== 'pin_reset')
        throw new UnauthorizedException('Invalid code');
  
      u.pin = parseInt(dto.newPin, 10);
      u.verCode = null;
      u.verCodeType = null;
      await this.subRepo.save(u);
      return { message: 'PIN reset.' };
    }
  
    async resetPin(userId: number, dto: ResetPinDto) {
      const u = await this.subRepo.findOne({ where: { id: userId } });
      if (!u || u.pin !== parseInt(dto.oldPin, 10)) throw new UnauthorizedException('Wrong old PIN');
  
      u.pin = parseInt(dto.newPin, 10);
      await this.subRepo.save(u);
      return { message: 'PIN changed.' };
    }
  
    async resetPasswordAuth(userId: number, dto: ResetPasswordAuthDto) {
      const u = await this.subRepo.findOne({ where: { id: userId } });
      if (!u || legacyHash(dto.oldPassword) !== u.spass) throw new UnauthorizedException('Wrong old password');
  
      u.spass = legacyHash(dto.newPassword);
      await this.subRepo.save(u);
      return { message: 'Password changed.' };
    }
  

  async logout(userId: number, token: string) {
    await redis.set(`blacklist:${token}`, 'blacklisted', 'EX', 60 * 60 * 24);
    await redis.del(`userToken:${userId}`);
    return { message: 'Logged out successfully.' };
  }
}
