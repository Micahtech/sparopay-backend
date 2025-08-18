import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Subscriber } from '../auth/subscriber.entity';
import { UpdateProfileDto } from './dto/update-profile.dto'; // <- moved to user/dto, not auth/dto
import { City } from './city.entity';
import { Address } from './address.entity';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(Subscriber)
    private readonly subRepo: Repository<Subscriber>,

    @InjectRepository(Address)
    private readonly addressRepo: Repository<Address>,

    @InjectRepository(City)
    private readonly cityRepo: Repository<City>,   // ✅ inject cityRepo
  ) {}

  // 👤 Profile
  async getProfile(userId: number) {
    const user = await this.subRepo.findOne({
      where: { id: userId },
      relations: ['addresses'],
    });
    if (!user) throw new NotFoundException('User not found');

    // Strip sensitive fields
    const { spass, pin, verCode, ...safeUser } = user;
    return safeUser;
  }

  // 💰 Wallet balance
  async getBalance(userId: number) {
    const user = await this.subRepo.findOne({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');
    return { balance: user.wallet };
  }

  // ✏️ Update Profile
  async updateProfile(userId: number, dto: UpdateProfileDto) {
    const user = await this.subRepo.findOne({
      where: { id: userId },
      relations: ['addresses'],
    });
    if (!user) throw new NotFoundException('User not found');

    // Update simple fields
    if (dto.fname) user.fname = dto.fname;
    if (dto.lname) user.lname = dto.lname;
    if (dto.email) user.email = dto.email;
    if (dto.phone) user.phone = dto.phone;
    if (dto.state) user.state = dto.state;
    if (dto.city) user.city = dto.city;
    if (dto.gender) user.gender = dto.gender;

    // Handle address
    if (dto.street) {
      const address = new Address();
      address.street = dto.street;
      address.subscriber = user;

      // optional city relation
      if (dto.city) {
        const cityEntity = await this.cityRepo.findOne({ where: { name: dto.city } });
        if (cityEntity) {
          address.city = cityEntity;
        }
      }

      // save new/updated address
      await this.addressRepo.save(address);

      // update user relation
      user.addresses = [address];
    }

    await this.subRepo.save(user);

    return { message: 'Profile updated successfully', user };
  }
}
