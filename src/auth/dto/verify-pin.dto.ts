// src/auth/dto/verify-pin.dto.ts
import { IsNotEmpty, IsNumberString } from 'class-validator';

export class VerifyPinDto {
  @IsNotEmpty()
  @IsNumberString()
  pin: string;
}
