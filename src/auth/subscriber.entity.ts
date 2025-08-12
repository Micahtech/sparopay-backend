import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity('subscribers')
export class Subscriber {
  @PrimaryGeneratedColumn({ name: 'sid' })
  id: number;

  @Column({ name: 'sapikey', nullable: true })
apiKey?: string;


 @Column({ name: 'sfname', nullable: true })
fname?: string;

@Column({ name: 'slname', nullable: true })
lname?: string;

@Column({ name: 'sfullname' })
fullName: string; // <- required now

  @Column({ name: 'semail' })
  email: string;

  @Column({ name: 'sphone' })
  phone: string;

  @Column({ name: 'spass' })
  spass: string;

  @Column({ name: 'sstate', nullable: true })
  state: string;

  @Column({ name: 'spin', type: 'varchar', nullable: true })
pin: string;



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

  @Column({ name: 'svercode', type: 'smallint', nullable: true })
verCode: number | null;

  @Column({ name: 'sregdate', type: 'timestamp' })
  regDate: Date;

  @Column({ name: 'slastactivity', type: 'timestamp', nullable: true })
  lastActivity: Date;

   @Column({ name: 'svercode_type', type: 'varchar', length: 30, nullable: true }) verCodeType: string | null; // NEW

@Column({ name: 'sreferal', type: 'varchar', nullable: true })
referal?: string | null;

@Column({ name: 'last_vercode_sent_at', type: 'timestamp', nullable: true })
lastVerCodeSentAt?: Date;

@Column({ name: 'vercode_resend_count', type: 'int', default: 0 })
verCodeResendCount: number;

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
