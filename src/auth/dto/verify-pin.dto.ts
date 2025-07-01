import { IsNumber } from 'class-validator';
export class VerifyPinDto { @IsNumber() pin: number; }
