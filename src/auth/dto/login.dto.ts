import { IsString } from 'class-validator';

export class LoginDto {
  @IsString() sPhone: string;
  @IsString() sPass: string;
}
