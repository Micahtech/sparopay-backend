import { Controller, Post, Body, UseGuards, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  RegisterDto, LoginDto, VerifyEmailDto, ResendVerificationDto,
  VerifyPinDto, CreatePinWithAuthDto, ForgotPasswordDto,
  ResetPasswordDto, ForgotPinDto, ResetPinDto, ResetPasswordAuthDto,
} from './dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.auth.register(dto);
  }

  @Post('verify-email')
  verifyEmail(@Body() dto: VerifyEmailDto) {
    return this.auth.verifyEmail(dto);
  }

  @Post('resend-verification-code')
  resendCode(@Body() dto: ResendVerificationDto) {
    return this.auth.resendVerificationCode(dto);
  }

  @Post('create-pin')
  createPin(@Body() dto: CreatePinWithAuthDto) {
    return this.auth.createPin(dto);
  }

  @Post('login')
  login(@Body() dto: LoginDto, @Req() req: Request) {
    return this.auth.login(dto, req);
  }

  @UseGuards(JwtAuthGuard)
  @Post('verify-pin')
  verifyPin(@Body() dto: VerifyPinDto, @Req() req) {
    return this.auth.verifyPin(dto, req.user.sub);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  logout(@Req() req) {
    const token = req.headers.authorization?.split(' ')[1];
    return this.auth.logout(req.user.sub, token);
  }

  @Post('forgot-password')
  forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.auth.forgotPassword(dto);
  }

  @Post('reset-password')
  resetPassword(@Body() dto: ResetPasswordDto) {
    return this.auth.resetPassword(dto);
  }

  @UseGuards(JwtAuthGuard)
  @Post('forgot-pin')
  forgotPin(@Body() dto: ForgotPinDto, @Req() req) {
    return this.auth.forgotPin(req.user.sub, dto);
  }

  @UseGuards(JwtAuthGuard)
  @Post('reset-pin')
  resetPin(@Body() dto: ResetPinDto, @Req() req) {
    return this.auth.resetPin(req.user.sub, dto);
  }

  @UseGuards(JwtAuthGuard)
  @Post('reset-password-auth')
  resetPasswordAuth(@Body() dto: ResetPasswordAuthDto, @Req() req) {
    return this.auth.resetPasswordAuth(req.user.sub, dto);
  }
}
