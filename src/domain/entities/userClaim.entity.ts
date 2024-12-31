import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity({ name: 'UserClaims', schema: 'identity' })
export class IdentityUserClaim {
  @PrimaryGeneratedColumn("increment")
  id: number;

  @Column()
  userId: string;

  @Column()
  claimType: string;

  @Column()
  claimValue: string;
}
