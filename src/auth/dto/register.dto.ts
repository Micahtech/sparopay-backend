import { IsEmail, IsString, Length, Matches } from 'class-validator';

export class RegisterDto {
  @IsString() @Length(2, 50) fname: string;
  @IsString() @Length(2, 50) lname: string;
  @IsEmail() email: string;
  @Matches(/^\d{10,15}$/) phone: string;
  @Length(6, 100) password: string;
  @Matches(/^\d{4}$/) transpin: string;
}
