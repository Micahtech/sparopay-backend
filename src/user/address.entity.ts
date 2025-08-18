import { Entity, Column, PrimaryGeneratedColumn, ManyToOne, JoinColumn } from 'typeorm';
import { Subscriber } from '../auth/subscriber.entity';
import { City } from './city.entity';

@Entity('addresses')
export class Address {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  street: string;

  @ManyToOne(() => City, { eager: true, nullable: true })
  @JoinColumn({ name: 'city_id' })
  city?: City;

  @ManyToOne(() => Subscriber, (subscriber) => subscriber.addresses, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'subscriber_id' })
  subscriber: Subscriber;
}
