// src/auth/dto/verify-pin.dto.ts
import { IsInt } from 'class-validator';

export class VerifyPinDto {
  @IsInt()
  pin: number;
}
