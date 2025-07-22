import { IsString, IsEmail, Matches, Length, IsNumber, IsInt, Min, Max, IsNotEmpty, } from 'class-validator';

export class CreatePinDto {
  @Matches(/^\d{4}$/, { message: 'PIN must be 4 digits' })
  pin: string;
}

export class ForgotPasswordDto {
  @IsEmail() email: string;
}

export class ForgotPinDto {
  @IsInt() code: number;
  @Length(6, 100) password: string;
  @Length(4, 4) newPin: string;
}

export class LoginDto {
  @IsString() sPhone: string;
  @IsString() sPass: string;
}

export class RegisterDto {
  @IsString() fname: string;
  @IsString() lname: string;
  @IsEmail() email: string;
  @Matches(/^\d{10,15}$/) phone: string;
  @IsString() state: string;
  @Length(6, 100) password: string;
}

export class ResendVerificationDto {
  @IsEmail() email: string;
}

export class ResetPasswordAuthDto {
  @Length(6, 100) oldPassword: string;
  @Length(6, 100) newPassword: string;
}


export class ResetPasswordDto {
  @IsEmail() email: string;
  @IsInt() @Min(1000) @Max(9999) code: number;
  @Length(6, 100) newPassword: string;
}

export class ResetPinDto {
  @Length(4, 4) oldPin: string;
  @Length(4, 4) newPin: string;
}

export class VerifyEmailDto {
  @IsEmail() email: string;
  @IsInt() @Min(1000) @Max(9999) code: number;
}

export class VerifyPinDto { @IsNumber() pin: number; }

export class CreatePinWithAuthDto extends CreatePinDto {
  @IsString()
  phone: string;

  @IsString()
  password: string;
}
export class ChangeEmailDto {
  @IsNumber()
  @IsNotEmpty()
  userId: number;

  @IsEmail()
  @IsNotEmpty()
  newEmail: string;
}