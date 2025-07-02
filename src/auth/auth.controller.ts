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
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';

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
@UseGuards(AuthGuard('jwt'))
createPin(@Body() dto: CreatePinDto, @Req() req: Request & { user: any }) {
  const userId = req.user.sub;
  return this.authService.createPin(userId, dto);
}


  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @Post('verify-pin')
  @UseGuards(AuthGuard('jwt'))
  verifyPin(@Body() dto: VerifyPinDto, @Req() req: Request & { user: any }) {
    const userId = req.user.sub;
    return this.authService.verifyPin(dto, userId);
  }
}
