import { Column, Entity } from 'typeorm';
import { IdentityUser } from 'typeorm-identity/domain';

export enum UserType {
    Admin = 'Admin',
    Standard = 'Standard',
    Guest = 'Guest',
}

@Entity()
export class AppUser extends IdentityUser<string> {
    @Column({
        type: 'varchar',
        enum: UserType,
        default: UserType.Standard
    })
    userType: UserType;
    
    @Column({ nullable: true })
    fullName?: string;
} 