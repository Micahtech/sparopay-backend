import { IsEmail, IsInt, Min, Max } from 'class-validator';
export class VerifyEmailDto {
  @IsEmail() email: string;
  @IsInt() @Min(1000) @Max(9999) code: number;
}
