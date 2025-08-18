import { IsOptional, IsString, IsEmail } from 'class-validator';

export class UpdateProfileDto {
  @IsOptional() @IsString()
  fname?: string;

  @IsOptional() @IsString()
  lname?: string;

  @IsOptional() @IsEmail()
  email?: string;

  @IsOptional() @IsString()
  phone?: string;

  @IsOptional() @IsString()
  state?: string;

  @IsOptional() @IsString()
  city?: string;

  @IsOptional() @IsString()
  gender?: string;

  @IsOptional() @IsString()
  street?: string; // address text
  
}
