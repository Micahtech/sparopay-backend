import { Controller, Post, Body, Request, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { AuthGuard } from '@nestjs/passport';
import { VerifyPinDto } from './dto/verify-pin.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('verify-pin')
  verifyPin(@Body() dto: VerifyPinDto, @Request() req) {
    return this.authService.verifyPin(dto.pin, req.user.sub);
  }
}
