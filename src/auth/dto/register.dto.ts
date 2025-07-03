import { IsString, IsEmail, Matches, Length } from 'class-validator';

export class RegisterDto {
  @IsString() fname: string;
  @IsString() lname: string;
  @IsEmail() email: string;
  @Matches(/^\d{10,15}$/) phone: string;
  @IsString() state: string;
  @Length(6, 100) password: string;
}
