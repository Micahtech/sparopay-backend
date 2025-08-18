import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { Subscriber } from '../auth/subscriber.entity';
import { Address } from './address.entity';
import { City } from './city.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Subscriber, Address, City])],
  controllers: [UserController],
  providers: [UserService],
})
export class UserModule {}
