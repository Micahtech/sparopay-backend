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
  VerifyPinDto, CreatePinDto, ForgotPasswordDto, ResetPasswordDto,
  ForgotPinDto, ResetPinDto, ResetPasswordAuthDto, ChangeEmailDto,
} from './dto';
import { createHash, randomUUID, } from 'crypto';
import Redis from 'ioredis';
import { Request } from 'express';
import * as geoip from 'geoip-lite';
import * as UAParser from 'ua-parser-js';
import { AuthGateway } from '../gateways/auth.gateway'; // adjust path as needed
import * as bcrypt from 'bcryptjs';


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
  private readonly authGateway: AuthGateway, // ✅ NO forwardRef needed
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

  if (exists) {
    throw new BadRequestException('Email or phone already exists');
  }

  // ✂️ Normalize and split full name
  const fullName = dto.fullName.trim().replace(/\s+/g, ' ');
  const nameParts = fullName.split(' ');

  if (nameParts.length < 2) {
    throw new BadRequestException('Full name must include at least two names');
  }

  const fname = nameParts[0];
  const lname = nameParts.slice(1).join(' '); // combine middle + last names

  const user = this.subRepo.create({
    fname,
    lname,
    fullName,
    email: dto.email,
    phone: dto.phone,
    spass: legacyHash(dto.password),
  referal: dto.referal || null,  // save null if not provided

    // Optional fields
    lastIP: dto.ip ?? '',

    // Defaults
    apiKey: randomUUID(),
    type: 1,
    regStatus: 0,
    wallet: 0,
    refWallet: 0,
    verCode: Math.floor(1000 + Math.random() * 9000),
    verCodeType: 'email_verification',
    regDate: new Date(),
    pinStatus: 0,
    bankNo: '',
    rolexBank: '',
    sterlingBank: '',
    fidelityBank: '',
    kudaBank: '',
    gtBank: '',
    bankName: '',
    bvn: '',
    nin: '',
    dob: '',
    kycStatus: '',
    accountReference: '',
    payvesselBank: '',
    paymentPoint: '',
    refStatus: '',
    lip: '',
    rip: '',
    groupId: '',
    emailSent: false,
    accountLimit: '',
    state: '',
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

const codeNumber = parseInt(String(dto.code), 10);
  if (isNaN(codeNumber)) throw new BadRequestException('Code must be a number');
  if (codeNumber < 1000 || codeNumber > 9999)
    throw new BadRequestException('Code must be a 4-digit number between 1000 and 9999');

 if (String(user.verCode) !== String(dto.code) || user.verCodeType !== 'email_verification') {
  throw new BadRequestException('Invalid code'); 
}
  user.regStatus = 2;
  user.verCode = null;
  user.verCodeType = null;
  await this.subRepo.save(user);

  return { message: 'Email verified successfully.' };
}


 async resendVerificationCode(dto: ResendVerificationDto) {
  const user = await this.subRepo.findOne({
    where: { email: dto.email },
  }) as Subscriber; // <-- explicitly cast to Subscriber

  if (!user) throw new BadRequestException('Email not found');
  if (user.regStatus >= 1) return { message: 'Already verified.' };

  const now = new Date();

  // These were causing TS errors; now they're recognized
  const lastSent = user.lastVerCodeSentAt ?? new Date(0);
  const resendCount = user.verCodeResendCount ?? 0;

  const waitTimes = [60, 90, 120, 150]; // in seconds
  const maxWait = waitTimes[Math.min(resendCount, waitTimes.length - 1)];
  const timeDiff = (now.getTime() - lastSent.getTime()) / 1000;

  if (timeDiff < maxWait) {
    const remaining = Math.ceil(maxWait - timeDiff);
    throw new BadRequestException(`Please wait ${remaining}s before resending code`);
  }

  user.verCode = Math.floor(1000 + Math.random() * 9000);
  user.verCodeType = 'email_verification';
  user.lastVerCodeSentAt = now;
  user.verCodeResendCount = resendCount + 1;

  await this.subRepo.save(user);

  await this.mailer.sendMail({
    to: user.email,
    subject: 'New Verification Code',
    text: `Your new verification code is ${user.verCode}`,
  });

  return { message: 'Verification code resent.' };
}

  
  async createPin(dto: CreatePinDto) {
  const user = await this.subRepo.findOne({ where: { phone: dto.phone } });

  if (!user) {
    throw new BadRequestException('User not found');
  }

  // Ensure user has verified email (regStatus === 2)
  if (user.regStatus !== 2) {
    throw new UnauthorizedException('User has not verified email');
  }

  // Prevent overwriting an existing PIN
  if (user.pin && user.pin.trim() !== '') {
    throw new BadRequestException('PIN already set for this user');
  }

  // PIN must be exactly 4 digits
  if (!/^\d{4}$/.test(dto.pin)) {
    throw new BadRequestException('PIN must be exactly 4 digits');
  }

  // Disallow weak/common PINs
  const weakPins = ['0000', '1234', '1111', '2222', '1212', '2580', '6969'];
  if (weakPins.includes(dto.pin)) {
    throw new BadRequestException('Choose a stronger PIN');
  }

  // Hash and store the PIN
  const hashedPin = await bcrypt.hash(dto.pin, 10);
  user.pin = hashedPin;
  user.pinStatus = 1;

  await this.subRepo.save(user);

  return { message: 'PIN created successfully.' };
}



async changeEmail(userId: number, dto: ChangeEmailDto) {
  const user = await this.subRepo.findOne({ where: { id: userId } });
  if (!user) throw new BadRequestException('User not found');

  // Check if new email is already taken by someone else
  const emailExists = await this.subRepo.findOne({ where: { email: dto.newEmail } });
  if (emailExists && emailExists.id !== userId) {
    throw new BadRequestException('Email already in use');
  }

  user.email = dto.newEmail;
  user.regStatus = 0; // reset verification status
  user.verCode = Math.floor(1000 + Math.random() * 9000);
  user.verCodeType = 'email_verification';

  await this.subRepo.save(user);

  await this.mailer.sendMail({
    to: user.email,
    subject: 'Verify your new email',
    text: `Your verification code is ${user.verCode}`,
  });

  return { message: 'Email changed. Verification code sent to new email.' };
}
async login(dto: LoginDto, req: Request) {
  const user = await this.subRepo.findOne({ where: { phone: dto.sPhone } });

  if (!user) {
    throw new UnauthorizedException('Wrong phone number');
  }

  if (legacyHash(dto.sPass) !== user.spass) {
    throw new UnauthorizedException('Wrong password');
  }if (user.regStatus === 0) {
  return {
    message: 'Verify your email.',
    user: { id: user.id, email: user.email, phone: user.phone } // <-- add id
  };
}


  if (user.regStatus === 2) {
    return {
      message: 'Set your PIN.',
      user: { email: user.email, phone: user.phone }
    };
  }

  // Only for regStatus === 1 (fully ready to login)
  await this.blacklistPreviousToken(user.id);

  const token = this.jwtService.sign({ sub: user.id, phone: user.phone, type: user.type });
  await redis.set(`userToken:${user.id}`, token, 'EX', 60 * 60 * 24);

  // Send login alert
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const geo = geoip.lookup(ip?.toString() || '');
  const parser = new UAParser.UAParser();
  parser.setUA(req.headers['user-agent'] ?? '');
  const ua = parser.getResult();

  this.authGateway.forceLogout(user.id);

  await this.mailer.sendMail({
    to: user.email,
    subject: 'New Login Detected',
    text: `New login to your account\nIP: ${ip}\nLocation: ${geo?.city || 'Unknown'}, ${geo?.country || 'N/A'}\nDevice: ${ua.device?.model || 'N/A'} (${ua.os.name} ${ua.os.version})\nTime: ${new Date().toLocaleString()}`
  });

  return {
    message: `Welcome, ${user.fname}`,
    token,
    user: this.clean(user),
    stype: user.type,
  };
}
async verifyPin(dto: VerifyPinDto, userId: number) {
  const user = await this.subRepo.findOne({ where: { id: userId } });
  if (!user || !user.pin) throw new UnauthorizedException('PIN not set');

  const isValid = await bcrypt.compare(String(dto.pin), String(user.pin));
  if (!isValid) throw new UnauthorizedException('Invalid PIN');

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
  if (!user || !(await bcrypt.compare(dto.password, user.spass)))
    throw new UnauthorizedException('Invalid password');
  if (user.verCode !== dto.code || user.verCodeType !== 'pin_reset')
    throw new UnauthorizedException('Invalid code');

  const hashedPin = await bcrypt.hash(dto.newPin, 10);
  user.pin = hashedPin;
  user.verCode = null;
  user.verCodeType = null;

  await this.subRepo.save(user);
  return { message: 'PIN reset.' };
}

async resetPin(userId: number, dto: ResetPinDto) {
  const user = await this.subRepo.findOne({ where: { id: userId } });
  if (!user || !user.pin) throw new UnauthorizedException('PIN not set');

  const isOldPinValid = await bcrypt.compare(dto.oldPin, user.pin);
  if (!isOldPinValid) throw new UnauthorizedException('Wrong old PIN');

  const newHashedPin = await bcrypt.hash(dto.newPin, 10);
  user.pin = newHashedPin;
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
