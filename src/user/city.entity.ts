import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity('cities')
export class City {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  name: string;

  @Column({ nullable: true })
  state?: string; // optional link to state
}
