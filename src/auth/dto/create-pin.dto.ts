import { IsString, Length, Matches } from 'class-validator';

export class CreatePinDto {
  @IsString()
  @Matches(/^\d{4}$/)
  @Length(4, 4)
  pin: string;
}
