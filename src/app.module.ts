import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';

import { Subscriber } from './subscribers/subscriber.entity';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    ConfigModule.forRoot(),
 TypeOrmModule.forRoot({
  type: 'postgres',
  host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || '5432', 10),
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  entities: [/* your entities */],
  synchronize: true,
  ssl: {
    rejectUnauthorized: false, // required for Render's self-signed SSL
  },
}),


    AuthModule,
  ],
})
export class AppModule {}
