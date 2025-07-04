import {
  Controller, Post, Body, UseGuards, Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ResendVerificationDto } from './dto/resend-verification.dto';
import { VerifyPinDto } from './dto/verify-pin.dto';
import { CreatePinDto } from './dto/create-pin.dto';
import { ForgotPasswordDto} from './dto/forgot-password.dto';
import { ResetPasswordDto} from './dto/reset-password.dto';
import { ForgotPinDto} from './dto/forgot-pin.dto';
import {ResetPinDto } from './dto/reset-pin.dto';
import { ResetPasswordAuthDto } from './dto/reset-password-auth.dto';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('verify-email')
  verifyEmail(@Body() dto: VerifyEmailDto) {
    return this.authService.verifyEmail(dto);
  }

  @Post('resend-verification-code')
  resendVerification(@Body() dto: ResendVerificationDto) {
    return this.authService.resendVerificationCode(dto);
  }

  @Post('create-pin')
  createPin(@Body() dto: CreatePinDto & { phone: string; password: string }) {
    return this.authService.createPin(dto);
  }

  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @Post('verify-pin')
  verifyPin(@Body() dto: VerifyPinDto, @Req() req: any) {
    const userId = req.user?.sub;
    return this.authService.verifyPin(dto, userId);
  }
  @Post('forgot-password')
forgotPassword(@Body() dto: ForgotPasswordDto) {
  return this.authService.forgotPassword(dto.email);
}

@Post('reset-password')
resetPassword(@Body() dto: ResetPasswordDto) {
  return this.authService.resetPassword(dto);
}

@Post('forgot-pin')
@UseGuards(AuthGuard('jwt'))
forgotPin(@Body() dto: ForgotPinDto, @Req() req: Request & { user: any }) {
  return this.authService.forgotPin(req.user.sub, dto);
}

@Post('reset-pin')
@UseGuards(AuthGuard('jwt'))
resetPin(@Body() dto: ResetPinDto, @Req() req: Request & { user: any }) {
  return this.authService.resetPin(req.user.sub, dto);
}

@Post('reset-password-auth')
@UseGuards(AuthGuard('jwt'))
resetPasswordAuth(@Body() dto: ResetPasswordAuthDto, @Req() req: Request & { user: any }) {
  return this.authService.resetPasswordAuth(req.user.sub, dto);
}

}
