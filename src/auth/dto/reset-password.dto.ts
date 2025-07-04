import { IsEmail, IsInt, Min, Max, Length } from 'class-validator';
export class ResetPasswordDto {
  @IsEmail() email: string;
  @IsInt() @Min(1000) @Max(9999) code: number;
  @Length(6, 100) newPassword: string;
}