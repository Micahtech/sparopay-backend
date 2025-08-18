import { Controller, Get, UseGuards, Req, Put, Body } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { UserService } from './user.service';
import { Request } from 'express';
import { UpdateProfileDto } from '../auth/dto/update-profile.dto';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  // 👤 "me" endpoint for logged in user
  @UseGuards(JwtAuthGuard)
  @Get('me')
  async getMe(@Req() req: Request) {
    return this.userService.getProfile(req.user!.sub);
  }

  // 💰 balance endpoint
  @UseGuards(JwtAuthGuard)
  @Get('balance')
  async getBalance(@Req() req: Request) {
    return this.userService.getBalance(req.user!.sub);
  }
   @UseGuards(JwtAuthGuard)
  @Put('update')
  async updateProfile(@Req() req: Request, @Body() dto: UpdateProfileDto) {
    return this.userService.updateProfile(req.user!.sub, dto);
  }
}
