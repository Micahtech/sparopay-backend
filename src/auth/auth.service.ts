import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
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

  // Register + send email verification code
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
      regStatus: 0,  // unverified
      emailSent: false,
      newPin: '',
    });

    await this.subRepo.save(sub);
    await this.mailer.sendMail({
      to: dto.email,
      subject: 'Verify your email',
      text: `Your verification code is ${code}`,
    });
    return { message: 'Registered. Check email for verification code.' };
  }

  // Verify email
  async verifyEmail(dto: VerifyEmailDto) {
    const user = await this.subRepo.findOne({ where: { email: dto.email } });
    if (!user) throw new BadRequestException('Email not found');
    if (user.regStatus >= 1) return { message: 'Already verified or active.' };
    if (user.verCode !== dto.code) throw new UnauthorizedException('Invalid code');

    user.regStatus = 2;
    await this.subRepo.save(user);
    return { message: 'Email verified successfully.' };
  }

  // Resend verification code (only if not verified)
  async resendVerificationCode(dto: ResendVerificationDto) {
    const user = await this.subRepo.findOne({ where: { email: dto.email } });
    if (!user) throw new BadRequestException('Email not found');
    if (user.regStatus >= 1)
      return { message: 'Already verified or active.' };

    const code = Math.floor(1000 + Math.random() * 9000);
    user.verCode = code;
    await this.subRepo.save(user);
    await this.mailer.sendMail({
      to: dto.email,
      subject: 'Resend Verification Code',
      text: `Your new code is ${code}`,
    });
    return { message: 'Verification code resent.' };
  }

  // Create PIN after email verification
  async createPin(dto: CreatePinWithAuthDto) {
    const user = await this.subRepo.findOne({ where: { phone: dto.phone } });
    if (!user) throw new BadRequestException('User not found');
    if (legacyHash(dto.password) !== user.spass)
      throw new UnauthorizedException('Invalid password');
    if (user.regStatus !== 2)
      throw new UnauthorizedException('Email must be verified first');
    if (dto.pin === '1234')
      throw new BadRequestException('PIN too weak');

    user.newPin = dto.pin;
    user.regStatus = 1;
    await this.subRepo.save(user);
    return { message: 'PIN created successfully.' };
  }

  // Login: partial or full based on regStatus
  async login(dto: LoginDto) {
    const user = await this.subRepo.findOne({ where: { phone: dto.sPhone } });
    if (!user || legacyHash(dto.sPass) !== user.spass)
      throw new UnauthorizedException('Invalid credentials');

    if (user.regStatus === 0)
      return { message: 'Please verify your email.' };
    if (user.regStatus === 2)
      return { message: 'Email verified. Please create a PIN.' };

    const token = this.jwtService.sign({
      sub: user.id,
      phone: user.phone,
      type: user.type,
    });

    const { spass, verCode, newPin, ...safeUser } = user;
    return { message: `Welcome, ${user.fname}`, token, user: safeUser };
  }

  // Verify PIN (must be logged in)
  async verifyPin(dto: VerifyPinDto, userId: number) {
    const user = await this.subRepo.findOne({ where: { id: userId } });
   if (!user || user.newPin !== String(dto.pin)) {
  throw new UnauthorizedException('Invalid PIN');
}

    return { message: 'PIN verified.' };
  }

  // Forgot password: send reset code
  async forgotPassword(dto: ForgotPasswordDto) {
    const user = await this.subRepo.findOne({ where: { email: dto.email } });
    if (!user) throw new BadRequestException('Email not found');

    const code = Math.floor(1000 + Math.random() * 9000);
    user.verCode = code;
    await this.subRepo.save(user);
    await this.mailer.sendMail({
      to: dto.email,
      subject: 'Password Reset Code',
      text: `Your reset code is ${code}`,
    });
    return { message: 'Password reset code sent.' };
  }

  // Reset password using code
  async resetPassword(dto: ResetPasswordDto) {
    const user = await this.subRepo.findOne({ where: { email: dto.email } });
    if (!user) throw new BadRequestException('Email not found');
    if (user.verCode !== dto.code) throw new UnauthorizedException('Invalid code');

    user.spass = legacyHash(dto.newPassword);
    await this.subRepo.save(user);
    return { message: 'Password reset successfully.' };
  }

  // Forgot PIN (when logged in): verify existing password + code
  async forgotPin(userId: number, dto: ForgotPinDto) {
    const user = await this.subRepo.findOne({ where: { id: userId } });
    if (!user) throw new BadRequestException('User not found');
    if (legacyHash(dto.password) !== user.spass || user.verCode !== dto.code)
      throw new UnauthorizedException('Invalid credentials');

    user.newPin = dto.newPin;
    await this.subRepo.save(user);
    return { message: 'PIN reset successfully.' };
  }

  // Reset PIN (when logged in): verify old PIN
  async resetPin(userId: number, dto: ResetPinDto) {
    const user = await this.subRepo.findOne({ where: { id: userId } });
    if (!user) throw new BadRequestException('User not found');
    if (user.newPin !== dto.oldPin)
      throw new UnauthorizedException('Old PIN is incorrect');

    user.newPin = dto.newPin;
    await this.subRepo.save(user);
    return { message: 'PIN changed successfully.' };
  }

  // Reset password (logged-in): verify old password
  async resetPasswordAuth(userId: number, dto: ResetPasswordAuthDto) {
    const user = await this.subRepo.findOne({ where: { id: userId } });
    if (!user) throw new BadRequestException('User not found');
    if (legacyHash(dto.oldPassword) !== user.spass)
      throw new UnauthorizedException('Old password is incorrect');

    user.spass = legacyHash(dto.newPassword);
    await this.subRepo.save(user);
    return { message: 'Password updated successfully.' };
  }
}
