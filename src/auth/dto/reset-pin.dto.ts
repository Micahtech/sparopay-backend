import {IsInt, Length } from 'class-validator';

export class ResetPinDto {
  @Length(4, 4) oldPin: string;
  @Length(4, 4) newPin: string;
}