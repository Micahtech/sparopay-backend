// src/auth/dto/verify-pin.dto.ts
import { IsNotEmpty, IsNumberString } from 'class-validator';

export class VerifyPinDto {
  pin: number;
}

