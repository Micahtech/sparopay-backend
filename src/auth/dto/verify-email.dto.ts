import { IsString, Length } from 'class-validator';

export class VerifyEmailDto {
  @IsString() phone: string;
  @Length(4, 4) code: string;
}
