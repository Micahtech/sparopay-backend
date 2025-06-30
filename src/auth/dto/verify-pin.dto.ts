import { IsNotEmpty, IsNumberString, Length } from 'class-validator';

export class VerifyPinDto {
  @IsNotEmpty()
  @IsNumberString()
  @Length(4, 6)
  pin: string;
}
