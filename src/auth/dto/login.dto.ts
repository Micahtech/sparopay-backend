// src/auth/dto/login.dto.ts
import { IsNotEmpty } from 'class-validator';

export class LoginDto {
  @IsNotEmpty()
  sPhone: string;

  @IsNotEmpty()
  sPass: string;
}
