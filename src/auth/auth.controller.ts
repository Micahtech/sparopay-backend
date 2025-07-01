import { Controller, Post, Body, UseGuards, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { VerifyPinDto } from './dto/verify-pin.dto';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }
@Post('verify-pin')
@UseGuards(AuthGuard('jwt'))
verifyPin(@Body() dto: VerifyPinDto, @Req() req: Request & { user: any }) {
  const userId = req.user.userId;
  return this.authService.verifyPin(dto.pin, userId);
}
}
