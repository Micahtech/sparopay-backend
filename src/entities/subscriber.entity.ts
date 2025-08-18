// src/subscribers/subscriber.entity.ts
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity('subscribers')
export class Subscriber {
  @PrimaryGeneratedColumn({ name: 'sId' })
  id: number;

  @Column({ name: 'sPhone' })
  phone: string;

  @Column({ name: 'sPass' })
  password: string;

  @Column({ name: 'sPin' })
  pin: number;

  @Column({ name: 'sEmail' })
  email: string;

  @Column({ name: 'sFname' })
  firstName: string;

  @Column({ name: 'sLname' })
  lastName: string;

  @Column({ name: 'sType' })
  role: number; // 1 = user, 2 = agent, etc.
}
