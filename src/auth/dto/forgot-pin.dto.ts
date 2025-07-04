import {IsInt, Length } from 'class-validator';

export class ForgotPinDto {
  @IsInt() code: number;
  @Length(6, 100) password: string;
  @Length(4, 4) newPin: string;
}