import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity('subscribers')
export class Subscriber {
  @PrimaryGeneratedColumn({ name: 'sid' })
  id: number;

  @Column({ name: 'sapikey' })
  apiKey: string;

  @Column({ name: 'sfname' })
  fname: string;

  @Column({ name: 'slname' })
  lname: string;

  @Column({ name: 'semail' })
  email: string;

  @Column({ name: 'sphone' })
  phone: string;

  @Column({ name: 'spass' })
  spass: string;

  @Column({ name: 'sstate' })
  state: string;

  @Column({ name: 'spin', type: 'int' })
  pin: number;
@Column({ name: 'snewpin', type: 'varchar', nullable: true })
newPin: string;


  @Column({ name: 'spinstatus', type: 'smallint' })
  pinStatus: number;

  @Column({ name: 'stype', type: 'smallint' })
  type: number;

  @Column({ name: 'swallet', type: 'float' })
  wallet: number;

  @Column({ name: 'srefwallet', type: 'float' })
  refWallet: number;

  @Column({ name: 'sbankno' })
  bankNo: string;

  @Column({ name: 'srolexbank' })
  rolexBank: string;

  @Column({ name: 'ssterlingbank' })
  sterlingBank: string;

  @Column({ name: 'sfidelitybank' })
  fidelityBank: string;

  @Column({ name: 'skudabank' })
  kudaBank: string;

  @Column({ name: 'sgtbank' })
  gtBank: string;

  @Column({ name: 'sbankname' })
  bankName: string;

  @Column({ name: 'sregstatus', type: 'smallint' })
  regStatus: number;

  @Column({ name: 'svercode', type: 'smallint' })
  verCode: number;

  @Column({ name: 'sregdate', type: 'timestamp' })
  regDate: Date;

  @Column({ name: 'slastactivity', type: 'timestamp', nullable: true })
  lastActivity: Date;

  @Column({ name: 'sreferal' })
  referal: string;

  @Column({ name: 'sbvn' })
  bvn: string;

  @Column({ name: 'snin' })
  nin: string;

  @Column({ name: 'sdob' })
  dob: string;

  @Column({ name: 'skycstatus' })
  kycStatus: string;

  @Column({ name: 'accountreference' })
  accountReference: string;

  @Column({ name: 'spayvesselbank' })
  payvesselBank: string;

  @Column({ name: 'spaymentpoint' })
  paymentPoint: string;

  @Column({ name: 'srefstatus' })
  refStatus: string;

  @Column({ name: 'slastip' })
  lastIP: string;

  @Column({ name: 'lip' })
  lip: string;

  @Column({ name: 'rip' })
  rip: string;

  @Column({ name: 'group_id' })
  groupId: string;

  @Column({ name: 'email_sent', type: 'boolean' })
  emailSent: boolean;

  @Column({ name: 'saccountlimit' })
  accountLimit: string;
}
