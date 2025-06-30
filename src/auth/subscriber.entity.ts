// src/auth/subscriber.entity.ts
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity('subscribers')
export class Subscriber {
  @PrimaryGeneratedColumn()
  sId: number;

  @Column({ nullable: true })
  sApiKey: string;

  @Column()
  sFname: string;

  @Column()
  sLname: string;

  @Column({ nullable: true })
  sEmail: string;

  @Column()
  sPhone: string;

  @Column()
  sPass: string;

  @Column()
  sState: string;

  @Column()
  sPin: number;
@Column({ type: 'smallint', nullable: true })
sType: number;

  // Add other columns as needed...
}
