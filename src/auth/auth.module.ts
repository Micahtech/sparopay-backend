import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { MailerModule } from '@nestjs-modules/mailer';
import { Subscriber } from './subscriber.entity';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    TypeOrmModule.forFeature([Subscriber]),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'default_jwt_secret',
      signOptions: { expiresIn: '7d' },
    }),
    MailerModule.forRoot({
      transport: {
        host: process.env.SMTP_HOST!,
        port: parseInt(process.env.SMTP_PORT!, 10),
        auth: {
          user: process.env.SMTP_USER!,
          pass: process.env.SMTP_PASS!,
        },
      },
      defaults: {
        from: `"Sparopay" <${process.env.SMTP_FROM}>`,
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
})
export class AuthModule {}
