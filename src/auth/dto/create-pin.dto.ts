import { Matches } from 'class-validator';

export class CreatePinDto {
  @Matches(/^\d{4}$/, { message: 'PIN must be 4 digits' })
  pin: string;
}
