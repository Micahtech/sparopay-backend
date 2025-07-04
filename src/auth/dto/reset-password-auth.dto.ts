import {IsInt, Length } from 'class-validator';
export class ResetPasswordAuthDto {
  @Length(6, 100) oldPassword: string;
  @Length(6, 100) newPassword: string;
}