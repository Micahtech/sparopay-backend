import { Matches, Length } from 'class-validator';

export class LoginDto {
  @Matches(/^\d{10,15}$/) sPhone: string;
  @Length(6, 100) sPass: string;
}
